use std::convert::Infallible;
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use http::header::{self, HeaderName};
use http::{HeaderMap, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use reqwest::Client;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio::time::sleep;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use url::Url;

type ResponseBody = Full<Bytes>;

const STANDALONE_BODY: &[u8] = br#"{"status":"ok","mode":"standalone"}"#;
const ENV_PROXY_PREFIX: &str = "LITEGATEWAY_Proxy__";
const ENV_RUST_PROXY_PREFIX: &str = "LITEGATEWAY_RustProxy__";

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("failed to install rustls ring crypto provider"))?;

    let settings = Settings::load()?;
    settings.validate()?;

    let state = Arc::new(AppState::new(&settings)?);
    let mut listener_tasks = JoinSet::new();

    if settings.enable_http {
        listener_tasks.spawn(run_http_listener(settings.http_port, state.clone()));
    }

    if settings.enable_https {
        let tls = build_tls_config(&settings, false)?;
        listener_tasks.spawn(run_tls_listener(settings.https_port, tls, state.clone()));
    }

    if settings.enable_mtls {
        let mtls = build_tls_config(&settings, true)?;
        listener_tasks.spawn(run_tls_listener(settings.mtls_port, mtls, state));
    }

    if listener_tasks.is_empty() {
        bail!("at least one endpoint must be enabled");
    }

    tokio::select! {
        outcome = listener_tasks.join_next() => {
            match outcome {
                Some(join_result) => join_result.context("listener task failed to join")??,
                None => bail!("no listener tasks were started"),
            }
        }
        signal = tokio::signal::ctrl_c() => {
            signal.context("failed to listen for shutdown signal")?;
            info!("shutdown requested");
        }
    }

    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

#[derive(Clone)]
struct Settings {
    enable_http: bool,
    http_port: u16,
    enable_https: bool,
    https_port: u16,
    enable_mtls: bool,
    mtls_port: u16,
    sleep_duration: Duration,
    server_cert_path: PathBuf,
    server_key_path: PathBuf,
    trusted_ca_path: PathBuf,
    upstream_url: Option<Url>,
    pass_connection_close: bool,
}

impl Settings {
    fn load() -> Result<Self> {
        let enable_http = parse_bool(&proxy_env_key("EnableHttp"), true)?;
        let enable_https = parse_bool(&proxy_env_key("EnableHttps"), true)?;
        let enable_mtls = parse_bool(&proxy_env_key("EnableMtls"), true)?;

        let http_port = parse_u16(&proxy_env_key("HttpPort"), 8080)?;
        let https_port = parse_u16(&proxy_env_key("HttpsPort"), 8443)?;
        let mtls_port = parse_u16(&proxy_env_key("MtlsPort"), 9443)?;

        let sleep_duration_ms = parse_u64(&proxy_env_key("SleepDurationMs"), 5_000)?;
        let upstream_url = optional_env(&proxy_env_key("UpstreamUrl"))
            .map(|value| Url::parse(&value).context("Proxy:UpstreamUrl must be an absolute URL"))
            .transpose()?;
        let pass_connection_close = parse_bool(&proxy_env_key("PassConnectionClose"), false)?;

        let server_certificate_hint = optional_env(&rust_proxy_env_key("ServerCertPath"))
            .or_else(|| optional_env(&proxy_env_key("ServerCertificatePemPath")))
            .or_else(|| optional_env(&proxy_env_key("ServerCertificatePath")));
        let (server_cert_path_raw, derived_server_key_path_raw) =
            derive_server_pem_paths(server_certificate_hint.as_deref());
        let server_key_path_raw = optional_env(&rust_proxy_env_key("ServerKeyPath"))
            .or_else(|| optional_env(&proxy_env_key("ServerPrivateKeyPath")))
            .map(PathBuf::from)
            .unwrap_or(derived_server_key_path_raw);

        let trusted_ca_path_raw = optional_env(&rust_proxy_env_key("TrustedCaPath"))
            .or_else(|| optional_env(&proxy_env_key("TrustedCaPath")))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("certs/generated/ca.cert.pem"));

        Ok(Self {
            enable_http,
            http_port,
            enable_https,
            https_port,
            enable_mtls,
            mtls_port,
            sleep_duration: Duration::from_millis(sleep_duration_ms),
            server_cert_path: resolve_path(server_cert_path_raw)?,
            server_key_path: resolve_path(server_key_path_raw)?,
            trusted_ca_path: resolve_path(trusted_ca_path_raw)?,
            upstream_url,
            pass_connection_close,
        })
    }

    fn validate(&self) -> Result<()> {
        if !self.enable_http && !self.enable_https && !self.enable_mtls {
            bail!("at least one endpoint must be enabled");
        }

        if (self.enable_http && self.enable_https && self.http_port == self.https_port)
            || (self.enable_http && self.enable_mtls && self.http_port == self.mtls_port)
            || (self.enable_https && self.enable_mtls && self.https_port == self.mtls_port)
        {
            bail!("enabled endpoint ports must be unique");
        }

        if self.enable_https || self.enable_mtls {
            ensure_readable_file(&self.server_cert_path, "server certificate")?;
            ensure_readable_file(&self.server_key_path, "server private key")?;
        }

        if self.enable_mtls {
            ensure_readable_file(&self.trusted_ca_path, "trusted CA certificate")?;
        }

        Ok(())
    }
}

#[derive(Clone)]
struct AppState {
    sleep_duration: Duration,
    upstream_url: Option<Url>,
    pass_connection_close: bool,
    client: Client,
}

impl AppState {
    fn new(settings: &Settings) -> Result<Self> {
        let mut builder = Client::builder()
            .use_rustls_tls()
            .http2_adaptive_window(true)
            .tcp_nodelay(true)
            .pool_max_idle_per_host(4_096)
            .pool_idle_timeout(Duration::from_secs(120))
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none());

        if settings.trusted_ca_path.is_file() {
            let ca_pem = std::fs::read(&settings.trusted_ca_path).with_context(|| {
                format!(
                    "failed to read trusted CA certificate: {}",
                    settings.trusted_ca_path.display()
                )
            })?;
            let ca_cert = reqwest::Certificate::from_pem(&ca_pem)
                .context("failed to parse trusted CA certificate for upstream TLS trust")?;
            builder = builder.add_root_certificate(ca_cert);
        }

        let client = builder
            .build()
            .context("failed to build upstream HTTP client")?;

        Ok(Self {
            sleep_duration: settings.sleep_duration,
            upstream_url: settings.upstream_url.clone(),
            pass_connection_close: settings.pass_connection_close,
            client,
        })
    }
}

async fn run_http_listener(port: u16, state: Arc<AppState>) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind HTTP listener on {addr}"))?;
    info!("HTTP listening on {addr}");

    accept_loop(listener, state, None).await
}

async fn run_tls_listener(
    port: u16,
    tls_config: Arc<ServerConfig>,
    state: Arc<AppState>,
) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind TLS listener on {addr}"))?;
    info!("TLS listening on {addr}");

    accept_loop(listener, state, Some(TlsAcceptor::from(tls_config))).await
}

async fn accept_loop(
    listener: TcpListener,
    state: Arc<AppState>,
    tls_acceptor: Option<TlsAcceptor>,
) -> Result<()> {
    loop {
        let (stream, peer_addr) = listener
            .accept()
            .await
            .context("failed to accept incoming connection")?;
        if let Err(error) = stream.set_nodelay(true) {
            warn!("failed to set TCP_NODELAY for {peer_addr}: {error}");
        }

        let state = state.clone();
        match tls_acceptor.clone() {
            Some(acceptor) => {
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            if let Err(error) = serve_stream(tls_stream, state).await {
                                warn!(
                                    "TLS connection processing failed for {peer_addr}: {error:#}"
                                );
                            }
                        }
                        Err(error) => {
                            warn!("TLS handshake failed for {peer_addr}: {error}");
                        }
                    }
                });
            }
            None => {
                tokio::spawn(async move {
                    if let Err(error) = serve_stream(stream, state).await {
                        warn!("HTTP connection processing failed for {peer_addr}: {error:#}");
                    }
                });
            }
        }
    }
}

async fn serve_stream<T>(stream: T, state: Arc<AppState>) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let service = service_fn(move |request| handle_request(request, state.clone()));
    AutoBuilder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(io, service)
        .await
        .map_err(|error| anyhow!("failed to serve connection: {error}"))
}

async fn handle_request(
    request: Request<Incoming>,
    state: Arc<AppState>,
) -> Result<Response<ResponseBody>, Infallible> {
    sleep(state.sleep_duration).await;

    let response = match state.upstream_url.as_ref() {
        Some(base_url) => forward_request(request, base_url, &state).await,
        None => standalone_response(&request, state.pass_connection_close),
    };

    Ok(response)
}

fn standalone_response(
    request: &Request<Incoming>,
    pass_connection_close: bool,
) -> Response<ResponseBody> {
    let body = Bytes::from_static(STANDALONE_BODY);
    let mut response = Response::new(Full::new(body.clone()));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    insert_content_length(response.headers_mut(), body.len());

    if pass_connection_close && connection_close_requested(request.headers()) {
        response.headers_mut().insert(
            header::CONNECTION,
            header::HeaderValue::from_static("close"),
        );
    }

    response
}

async fn forward_request(
    mut request: Request<Incoming>,
    upstream_url: &Url,
    state: &AppState,
) -> Response<ResponseBody> {
    let target_url = match build_target_url(upstream_url, request.uri()) {
        Ok(url) => url,
        Err(error) => {
            warn!("failed to build upstream URL: {error:#}");
            return empty_response(StatusCode::BAD_GATEWAY);
        }
    };

    let mut upstream = state
        .client
        .request(request.method().clone(), target_url.clone());
    for (name, value) in request.headers() {
        if should_skip_request_header(name) {
            continue;
        }
        upstream = upstream.header(name, value);
    }

    if state.pass_connection_close && connection_close_requested(request.headers()) {
        upstream = upstream.header(header::CONNECTION, "close");
    }

    let body = match request.body_mut().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(error) => {
            warn!("failed to read downstream request body: {error}");
            return empty_response(StatusCode::BAD_REQUEST);
        }
    };
    if !body.is_empty() {
        upstream = upstream.body(body);
    }

    let upstream_response = match upstream.send().await {
        Ok(response) => response,
        Err(error) => {
            let status = if error.is_timeout() {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::BAD_GATEWAY
            };
            warn!("upstream request failed for {target_url}: {error}");
            return empty_response(status);
        }
    };

    let status = StatusCode::from_u16(upstream_response.status().as_u16())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let upstream_headers = upstream_response.headers().clone();
    let upstream_connection_close =
        state.pass_connection_close && connection_close_requested(upstream_response.headers());
    let upstream_body = match upstream_response.bytes().await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read upstream response body: {error}");
            return empty_response(StatusCode::BAD_GATEWAY);
        }
    };

    let upstream_body_len = upstream_body.len();
    let mut response = Response::new(Full::new(upstream_body));
    *response.status_mut() = status;
    copy_response_headers(&upstream_headers, response.headers_mut());
    insert_content_length(response.headers_mut(), upstream_body_len);

    if upstream_connection_close {
        response.headers_mut().insert(
            header::CONNECTION,
            header::HeaderValue::from_static("close"),
        );
    }

    response
}

fn empty_response(status: StatusCode) -> Response<ResponseBody> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = status;
    response
}

fn copy_response_headers(source: &HeaderMap, destination: &mut HeaderMap) {
    for (name, value) in source {
        if should_skip_response_header(name) {
            continue;
        }
        destination.append(name, value.clone());
    }
}

fn insert_content_length(headers: &mut HeaderMap, length: usize) {
    if let Ok(value) = header::HeaderValue::from_str(&length.to_string()) {
        headers.insert(header::CONTENT_LENGTH, value);
    }
}

fn should_skip_request_header(name: &HeaderName) -> bool {
    name == header::HOST || is_hop_by_hop_header(name)
}

fn should_skip_response_header(name: &HeaderName) -> bool {
    is_hop_by_hop_header(name)
}

fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    name == header::CONNECTION
        || name.as_str().eq_ignore_ascii_case("keep-alive")
        || name == header::PROXY_AUTHENTICATE
        || name == header::PROXY_AUTHORIZATION
        || name == header::TE
        || name == header::TRAILER
        || name == header::TRANSFER_ENCODING
        || name == header::UPGRADE
        || name.as_str().eq_ignore_ascii_case("proxy-connection")
}

fn connection_close_requested(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|value| value.trim().eq_ignore_ascii_case("close"))
}

fn build_target_url(base_url: &Url, request_uri: &Uri) -> Result<Url> {
    let mut url = base_url.clone();
    let combined_path = combine_paths(base_url.path(), request_uri.path());
    url.set_path(&combined_path);
    url.set_query(request_uri.query());
    Ok(url)
}

fn combine_paths(base_path: &str, request_path: &str) -> String {
    if base_path == "/" {
        return if request_path.is_empty() {
            "/".to_string()
        } else {
            request_path.to_string()
        };
    }

    if request_path.is_empty() || request_path == "/" {
        return base_path.to_string();
    }

    if base_path.ends_with('/') {
        if request_path.starts_with('/') {
            format!("{}{}", &base_path[..base_path.len() - 1], request_path)
        } else {
            format!("{base_path}{request_path}")
        }
    } else if request_path.starts_with('/') {
        format!("{base_path}{request_path}")
    } else {
        format!("{base_path}/{request_path}")
    }
}

fn build_tls_config(settings: &Settings, require_client_cert: bool) -> Result<Arc<ServerConfig>> {
    let cert_chain = load_certificates(&settings.server_cert_path)?;
    let private_key = load_private_key(&settings.server_key_path)?;

    let mut tls_config = if require_client_cert {
        let mut root_store = RootCertStore::empty();
        for cert in load_certificates(&settings.trusted_ca_path)? {
            root_store
                .add(cert)
                .map_err(|error| anyhow!("failed to add trusted CA certificate: {error}"))?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .context("failed to build client certificate verifier")?;
        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(cert_chain, private_key)
            .context("failed to build mTLS server config")?
    } else {
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .context("failed to build TLS server config")?
    };

    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(tls_config))
}

fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open certificate file: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("failed to read certificate chain from {}", path.display()))?;
    if certs.is_empty() {
        bail!("no certificates found in {}", path.display());
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open private key file: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("failed to read private key from {}", path.display()))?
        .ok_or_else(|| anyhow!("no private key found in {}", path.display()))?;
    Ok(key)
}

fn parse_bool(name: &str, fallback: bool) -> Result<bool> {
    match optional_env(name) {
        Some(value) => value
            .parse::<bool>()
            .with_context(|| format!("{name} must be true or false")),
        None => Ok(fallback),
    }
}

fn parse_u16(name: &str, fallback: u16) -> Result<u16> {
    match optional_env(name) {
        Some(value) => {
            let parsed = value
                .parse::<u16>()
                .with_context(|| format!("{name} must be a valid port between 1 and 65535"))?;
            if parsed == 0 {
                bail!("{name} must be a valid port between 1 and 65535");
            }
            Ok(parsed)
        }
        None => Ok(fallback),
    }
}

fn parse_u64(name: &str, fallback: u64) -> Result<u64> {
    match optional_env(name) {
        Some(value) => value
            .parse::<u64>()
            .with_context(|| format!("{name} must be a positive integer")),
        None => Ok(fallback),
    }
}

fn optional_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn resolve_path(path: PathBuf) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        let cwd = env::current_dir().context("failed to read current directory")?;
        let cwd_candidate = cwd.join(&path);
        if cwd_candidate.exists() {
            return Ok(cwd_candidate);
        }

        let project_root_candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .map(|root| root.join(&path));
        if let Some(project_candidate) = project_root_candidate {
            return Ok(project_candidate);
        }

        Ok(cwd_candidate)
    }
}

fn derive_server_pem_paths(server_certificate_hint: Option<&str>) -> (PathBuf, PathBuf) {
    let default_cert = PathBuf::from("certs/generated/server.cert.pem");
    let default_key = PathBuf::from("certs/generated/server.key.pem");

    let Some(hint) = server_certificate_hint else {
        return (default_cert, default_key);
    };

    let hint_path = PathBuf::from(hint);
    if hint_path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("pfx"))
    {
        let directory = hint_path.parent().unwrap_or_else(|| Path::new("."));
        return (
            directory.join("server.cert.pem"),
            directory.join("server.key.pem"),
        );
    }

    let key_path = derive_server_key_path_from_cert(&hint_path);
    (hint_path, key_path)
}

fn derive_server_key_path_from_cert(cert_path: &Path) -> PathBuf {
    let directory = cert_path.parent().unwrap_or_else(|| Path::new("."));
    let Some(file_name) = cert_path.file_name().and_then(|name| name.to_str()) else {
        return directory.join("server.key.pem");
    };

    if let Some(prefix) = file_name.strip_suffix(".cert.pem") {
        return directory.join(format!("{prefix}.key.pem"));
    }

    directory.join("server.key.pem")
}

fn ensure_readable_file(path: &Path, description: &str) -> Result<()> {
    if !path.is_file() {
        bail!("{description} file does not exist: {}", path.display());
    }
    Ok(())
}

fn proxy_env_key(suffix: &str) -> String {
    format!("{ENV_PROXY_PREFIX}{suffix}")
}

fn rust_proxy_env_key(suffix: &str) -> String {
    format!("{ENV_RUST_PROXY_PREFIX}{suffix}")
}
