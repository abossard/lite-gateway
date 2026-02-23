using System.Net;
using System.Collections.Concurrent;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Net.Http.Headers;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddEnvironmentVariables(prefix: "LITEGATEWAY_");
builder.Logging.AddFilter("Microsoft.AspNetCore.Hosting.Diagnostics", LogLevel.None);
builder.Logging.AddFilter("Microsoft.Hosting.Lifetime", LogLevel.Warning);

var settings = ProxySettings.Load(builder.Configuration, builder.Environment.ContentRootPath);
var serverCertificate = LoadPkcs12Certificate(
    settings.ServerCertificatePath,
    settings.ServerCertificatePassword);
var serverCertificateContext = CreateServerCertificateContext(serverCertificate);
var trustedCaCertificate = X509CertificateLoader.LoadCertificateFromFile(settings.TrustedCaPath);

builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Limits.MaxConcurrentConnections = 20_000;
    options.Limits.MaxConcurrentUpgradedConnections = 20_000;
    options.Limits.MaxRequestBodySize = null;
    options.Limits.Http2.MaxStreamsPerConnection = 1_024;
    options.Limits.MinRequestBodyDataRate = null;
    options.Limits.MinResponseDataRate = null;

    if (settings.EnableHttp)
    {
        options.ListenAnyIP(settings.HttpPort, listen =>
        {
            listen.Protocols = HttpProtocols.Http1;
        });
    }

    if (settings.EnableHttps)
    {
        options.ListenAnyIP(settings.HttpsPort, listen =>
        {
            listen.Protocols = HttpProtocols.Http1AndHttp2;
            listen.UseHttps(https =>
            {
                https.ServerCertificate = serverCertificate;
                https.OnAuthenticate = (_, sslOptions) =>
                {
                    sslOptions.ServerCertificateContext = serverCertificateContext;
                };
                https.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                https.ClientCertificateMode = ClientCertificateMode.NoCertificate;
            });
        });
    }

    if (settings.EnableMtls)
    {
        options.ListenAnyIP(settings.MtlsPort, listen =>
        {
            listen.Protocols = HttpProtocols.Http1AndHttp2;
            listen.UseHttps(https =>
            {
                https.ServerCertificate = serverCertificate;
                https.OnAuthenticate = (_, sslOptions) =>
                {
                    sslOptions.ServerCertificateContext = serverCertificateContext;
                };
                https.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                https.ClientCertificateValidation = (certificate, _, _) =>
                    ValidateClientCertificate(certificate, trustedCaCertificate);
            });
        });
    }
});

using var runtime = ProxyRuntime.Create(settings);

var app = builder.Build();
app.Run(context => HandleAsync(context, runtime));
await app.RunAsync();

static async Task HandleAsync(HttpContext context, ProxyRuntime runtime)
{
    if (runtime.UpstreamUri is null)
    {
        ReadOnlyMemory<byte> requestBody;
        try
        {
            requestBody = await ReadRequestBodyAsync(context.Request, context.RequestAborted);
            await Task.Delay(runtime.SleepDuration, context.RequestAborted);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        await WriteStandaloneResponseAsync(context, runtime, requestBody);
        return;
    }

    try
    {
        await Task.Delay(runtime.SleepDuration, context.RequestAborted);
        await ForwardAsync(context, runtime);
    }
    catch (OperationCanceledException)
    {
    }
}

static async Task<ReadOnlyMemory<byte>> ReadRequestBodyAsync(HttpRequest request, CancellationToken cancellationToken)
{
    if (request.Body is null)
    {
        return ReadOnlyMemory<byte>.Empty;
    }

    using var buffer = new MemoryStream();
    await request.Body.CopyToAsync(buffer, cancellationToken);
    return buffer.ToArray();
}

static async Task WriteStandaloneResponseAsync(HttpContext context, ProxyRuntime runtime, ReadOnlyMemory<byte> requestBody)
{
    context.Response.StatusCode = StatusCodes.Status200OK;
    context.Response.ContentType = string.IsNullOrWhiteSpace(context.Request.ContentType)
        ? "application/json"
        : context.Request.ContentType;
    context.Response.ContentLength = requestBody.Length;

    if (runtime.PassConnectionClose && IsConnectionCloseRequested(context.Request.Headers))
    {
        context.Response.Headers.Connection = "close";
    }

    await context.Response.BodyWriter.WriteAsync(requestBody, context.RequestAborted);
}

static async Task ForwardAsync(HttpContext context, ProxyRuntime runtime)
{
    var targetUri = BuildTargetUri(runtime.UpstreamUri!, context.Request.Path, context.Request.QueryString);
    using var upstreamRequest = CreateUpstreamRequest(context.Request, targetUri, runtime.PassConnectionClose);

    try
    {
        using var upstreamResponse = await runtime.HttpInvoker.SendAsync(upstreamRequest, context.RequestAborted);
        context.Response.StatusCode = (int)upstreamResponse.StatusCode;
        CopyResponseHeaders(upstreamResponse, context.Response, runtime.PassConnectionClose);

        if (upstreamResponse.Content is not null)
        {
            await upstreamResponse.Content.CopyToAsync(context.Response.Body, context.RequestAborted);
        }
    }
    catch (OperationCanceledException) when (!context.RequestAborted.IsCancellationRequested)
    {
        context.Response.StatusCode = StatusCodes.Status504GatewayTimeout;
    }
    catch (HttpRequestException)
    {
        context.Response.StatusCode = StatusCodes.Status502BadGateway;
    }
}

static HttpRequestMessage CreateUpstreamRequest(HttpRequest request, Uri targetUri, bool passConnectionClose)
{
    var upstreamRequest = new HttpRequestMessage(GetHttpMethod(request.Method), targetUri);

    if (request.ContentLength is > 0 || request.Headers.ContainsKey(HeaderNames.TransferEncoding))
    {
        upstreamRequest.Content = new StreamContent(request.Body);
    }

    foreach (var header in request.Headers)
    {
        if (ShouldSkipRequestHeader(header.Key))
        {
            continue;
        }

        var values = header.Value.ToArray();
        if (!upstreamRequest.Headers.TryAddWithoutValidation(header.Key, values) && upstreamRequest.Content is not null)
        {
            upstreamRequest.Content.Headers.TryAddWithoutValidation(header.Key, values);
        }
    }

    upstreamRequest.Headers.Host = targetUri.Authority;

    if (passConnectionClose && IsConnectionCloseRequested(request.Headers))
    {
        upstreamRequest.Headers.ConnectionClose = true;
    }

    return upstreamRequest;
}

static Uri BuildTargetUri(Uri upstreamUri, PathString requestPath, QueryString requestQuery)
{
    var builder = new UriBuilder(upstreamUri)
    {
        Path = CombinePaths(upstreamUri.AbsolutePath, requestPath.Value),
        Query = requestQuery.HasValue ? requestQuery.Value![1..] : string.Empty
    };

    return builder.Uri;
}

static string CombinePaths(string basePath, string? requestPath)
{
    requestPath ??= string.Empty;

    if (basePath == "/")
    {
        return string.IsNullOrEmpty(requestPath) ? "/" : requestPath;
    }

    if (string.IsNullOrEmpty(requestPath) || requestPath == "/")
    {
        return basePath;
    }

    if (basePath.EndsWith('/'))
    {
        return requestPath.StartsWith('/')
            ? $"{basePath[..^1]}{requestPath}"
            : $"{basePath}{requestPath}";
    }

    return requestPath.StartsWith('/')
        ? $"{basePath}{requestPath}"
        : $"{basePath}/{requestPath}";
}

static void CopyResponseHeaders(HttpResponseMessage upstreamResponse, HttpResponse downstreamResponse, bool passConnectionClose)
{
    foreach (var header in upstreamResponse.Headers)
    {
        if (ShouldSkipResponseHeader(header.Key))
        {
            continue;
        }

        foreach (var value in header.Value)
        {
            downstreamResponse.Headers.Append(header.Key, value);
        }
    }

    if (upstreamResponse.Content is not null)
    {
        foreach (var header in upstreamResponse.Content.Headers)
        {
            if (ShouldSkipResponseHeader(header.Key))
            {
                continue;
            }

            foreach (var value in header.Value)
            {
                downstreamResponse.Headers.Append(header.Key, value);
            }
        }
    }

    downstreamResponse.Headers.Remove(HeaderNames.TransferEncoding);

    if (passConnectionClose && upstreamResponse.Headers.ConnectionClose == true)
    {
        downstreamResponse.Headers.Connection = "close";
    }
}

static HttpMethod GetHttpMethod(string method) =>
    method switch
    {
        "GET" => HttpMethod.Get,
        "POST" => HttpMethod.Post,
        "PUT" => HttpMethod.Put,
        "DELETE" => HttpMethod.Delete,
        "PATCH" => HttpMethod.Patch,
        "HEAD" => HttpMethod.Head,
        "OPTIONS" => HttpMethod.Options,
        "TRACE" => HttpMethod.Trace,
        _ => HttpMethod.Parse(method)
    };

static bool ShouldSkipRequestHeader(string headerName) =>
    headerName.Equals(HeaderNames.Host, StringComparison.OrdinalIgnoreCase) || IsHopByHopHeader(headerName);

static bool ShouldSkipResponseHeader(string headerName) => IsHopByHopHeader(headerName);

static bool IsHopByHopHeader(string headerName) =>
    headerName.Equals(HeaderNames.Connection, StringComparison.OrdinalIgnoreCase) ||
    headerName.Equals(HeaderNames.KeepAlive, StringComparison.OrdinalIgnoreCase) ||
    headerName.Equals(HeaderNames.ProxyAuthenticate, StringComparison.OrdinalIgnoreCase) ||
    headerName.Equals(HeaderNames.ProxyAuthorization, StringComparison.OrdinalIgnoreCase) ||
    headerName.Equals(HeaderNames.TE, StringComparison.OrdinalIgnoreCase) ||
    headerName.Equals(HeaderNames.Trailer, StringComparison.OrdinalIgnoreCase) ||
    headerName.Equals(HeaderNames.TransferEncoding, StringComparison.OrdinalIgnoreCase) ||
    headerName.Equals(HeaderNames.Upgrade, StringComparison.OrdinalIgnoreCase) ||
    headerName.Equals("Proxy-Connection", StringComparison.OrdinalIgnoreCase);

static bool IsConnectionCloseRequested(IHeaderDictionary headers)
{
    if (!headers.TryGetValue(HeaderNames.Connection, out var values))
    {
        return false;
    }

    foreach (var value in values)
    {
        if (value?.Contains("close", StringComparison.OrdinalIgnoreCase) == true)
        {
            return true;
        }
    }

    return false;
}

static X509Certificate2 LoadPkcs12Certificate(string path, string? password)
{
    try
    {
        return X509CertificateLoader.LoadPkcs12FromFile(path, password, X509KeyStorageFlags.EphemeralKeySet);
    }
    catch (PlatformNotSupportedException)
    {
        return X509CertificateLoader.LoadPkcs12FromFile(path, password);
    }
}

static SslStreamCertificateContext CreateServerCertificateContext(X509Certificate2 serverCertificate)
{
    return SslStreamCertificateContext.Create(serverCertificate, new X509Certificate2Collection());
}

static bool ValidateClientCertificate(X509Certificate2? certificate, X509Certificate2 trustedCaCertificate)
{
    if (certificate is null || !HasClientAuthenticationUsage(certificate))
    {
        return false;
    }

    var cacheKey = $"{certificate.Thumbprint}:{certificate.NotAfter.Ticks}:{trustedCaCertificate.Thumbprint}";
    if (CertificateValidationCache.ClientCertificate.TryGetValue(cacheKey, out var cachedResult))
    {
        return cachedResult;
    }

    using var chain = new X509Chain();
    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
    chain.ChainPolicy.CustomTrustStore.Add(trustedCaCertificate);
    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
    chain.ChainPolicy.DisableCertificateDownloads = true;

    if (!chain.Build(certificate))
    {
        CertificateValidationCache.ClientCertificate[cacheKey] = false;
        return false;
    }

    var root = chain.ChainElements.Count == 0 ? null : chain.ChainElements[^1].Certificate;
    var isValid = root is not null &&
                  string.Equals(root.Thumbprint, trustedCaCertificate.Thumbprint, StringComparison.OrdinalIgnoreCase);
    CertificateValidationCache.ClientCertificate[cacheKey] = isValid;
    return isValid;
}

static bool HasClientAuthenticationUsage(X509Certificate2 certificate)
{
    foreach (var extension in certificate.Extensions)
    {
        if (extension is not X509EnhancedKeyUsageExtension eku)
        {
            continue;
        }

        foreach (var usage in eku.EnhancedKeyUsages)
        {
            if (usage.Value == "1.3.6.1.5.5.7.3.2")
            {
                return true;
            }
        }

        return false;
    }

    return false;
}

file sealed class ProxySettings
{
    public bool EnableHttp { get; init; }
    public int HttpPort { get; init; }
    public bool EnableHttps { get; init; }
    public int HttpsPort { get; init; }
    public bool EnableMtls { get; init; }
    public int MtlsPort { get; init; }
    public TimeSpan SleepDuration { get; init; }
    public string ServerCertificatePath { get; init; } = string.Empty;
    public string ServerCertificatePassword { get; init; } = string.Empty;
    public string TrustedCaPath { get; init; } = string.Empty;
    public string? OutboundClientCertificatePath { get; init; }
    public string? OutboundClientCertificatePassword { get; init; }
    public Uri? UpstreamUri { get; init; }
    public bool PassConnectionClose { get; init; }

    public static ProxySettings Load(IConfiguration configuration, string contentRootPath)
    {
        var section = configuration.GetSection("Proxy");
        var upstreamUrl = section["UpstreamUrl"];
        Uri? upstreamUri = null;

        if (!string.IsNullOrWhiteSpace(upstreamUrl) && !Uri.TryCreate(upstreamUrl, UriKind.Absolute, out upstreamUri))
        {
            throw new InvalidOperationException("Proxy:UpstreamUrl must be an absolute URI.");
        }

        var legacyPortValue = section["Port"];
        var enableHttp = ParseBool(section["EnableHttp"], true, "Proxy:EnableHttp");
        var enableHttps = ParseBool(section["EnableHttps"], true, "Proxy:EnableHttps");
        var enableMtls = ParseBool(section["EnableMtls"], true, "Proxy:EnableMtls");

        if (!enableHttp && !enableHttps && !enableMtls)
        {
            throw new InvalidOperationException("At least one endpoint must be enabled.");
        }

        var httpPort = ParseInt(section["HttpPort"], 8080, 1, 65535, "Proxy:HttpPort");
        var httpsPort = ParseInt(section["HttpsPort"], 8443, 1, 65535, "Proxy:HttpsPort");
        var mtlsPort = ParseInt(section["MtlsPort"] ?? legacyPortValue, 9443, 1, 65535, "Proxy:MtlsPort");

        if ((enableHttp && enableHttps && httpPort == httpsPort) ||
            (enableHttp && enableMtls && httpPort == mtlsPort) ||
            (enableHttps && enableMtls && httpsPort == mtlsPort))
        {
            throw new InvalidOperationException("Proxy ports must be unique for enabled endpoints.");
        }

        return new ProxySettings
        {
            EnableHttp = enableHttp,
            HttpPort = httpPort,
            EnableHttps = enableHttps,
            HttpsPort = httpsPort,
            EnableMtls = enableMtls,
            MtlsPort = mtlsPort,
            SleepDuration = TimeSpan.FromMilliseconds(ParseInt(section["SleepDurationMs"], 5000, 0, 600_000, "Proxy:SleepDurationMs")),
            ServerCertificatePath = ResolveRequiredPath(section["ServerCertificatePath"], contentRootPath, "Proxy:ServerCertificatePath"),
            ServerCertificatePassword = section["ServerCertificatePassword"] ?? string.Empty,
            TrustedCaPath = ResolveRequiredPath(section["TrustedCaPath"], contentRootPath, "Proxy:TrustedCaPath"),
            OutboundClientCertificatePath = ResolveOptionalPath(section["OutboundClientCertificatePath"], contentRootPath),
            OutboundClientCertificatePassword = section["OutboundClientCertificatePassword"],
            UpstreamUri = upstreamUri,
            PassConnectionClose = ParseBool(section["PassConnectionClose"], false, "Proxy:PassConnectionClose")
        };
    }

    private static int ParseInt(string? value, int fallback, int min, int max, string settingName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        if (int.TryParse(value, out var parsed) && parsed >= min && parsed <= max)
        {
            return parsed;
        }

        throw new InvalidOperationException($"{settingName} must be between {min} and {max}.");
    }

    private static bool ParseBool(string? value, bool fallback, string settingName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        if (bool.TryParse(value, out var parsed))
        {
            return parsed;
        }

        throw new InvalidOperationException($"{settingName} must be true or false.");
    }

    private static string ResolveRequiredPath(string? path, string contentRootPath, string settingName)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new InvalidOperationException($"{settingName} is required.");
        }

        return ResolvePath(path, contentRootPath);
    }

    private static string? ResolveOptionalPath(string? path, string contentRootPath) =>
        string.IsNullOrWhiteSpace(path) ? null : ResolvePath(path, contentRootPath);

    private static string ResolvePath(string path, string contentRootPath) =>
        Path.GetFullPath(Path.IsPathRooted(path) ? path : Path.Combine(contentRootPath, path));
}

file static class CertificateValidationCache
{
    public static readonly ConcurrentDictionary<string, bool> ClientCertificate = new(StringComparer.Ordinal);
}

file sealed class ProxyRuntime : IDisposable
{
    private readonly SocketsHttpHandler _httpHandler;
    private readonly X509Certificate2? _outboundClientCertificate;

    private ProxyRuntime(
        TimeSpan sleepDuration,
        Uri? upstreamUri,
        bool passConnectionClose,
        SocketsHttpHandler httpHandler,
        HttpMessageInvoker httpInvoker,
        X509Certificate2? outboundClientCertificate)
    {
        SleepDuration = sleepDuration;
        UpstreamUri = upstreamUri;
        PassConnectionClose = passConnectionClose;
        _httpHandler = httpHandler;
        HttpInvoker = httpInvoker;
        _outboundClientCertificate = outboundClientCertificate;
    }

    public TimeSpan SleepDuration { get; }
    public Uri? UpstreamUri { get; }
    public bool PassConnectionClose { get; }
    public HttpMessageInvoker HttpInvoker { get; }

    public static ProxyRuntime Create(ProxySettings settings)
    {
        X509Certificate2? outboundClientCertificate = null;
        if (!string.IsNullOrWhiteSpace(settings.OutboundClientCertificatePath))
        {
            outboundClientCertificate = LoadPkcs12CertificateWithFallback(
                settings.OutboundClientCertificatePath,
                settings.OutboundClientCertificatePassword);
        }

        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            EnableMultipleHttp2Connections = true,
            MaxConnectionsPerServer = 4_096,
            PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
            PooledConnectionLifetime = TimeSpan.FromMinutes(15),
            UseCookies = false
        };
        handler.SslOptions.EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;

        if (outboundClientCertificate is not null)
        {
            handler.SslOptions.ClientCertificates = [outboundClientCertificate];
        }

        var invoker = new HttpMessageInvoker(handler, disposeHandler: false);
        return new ProxyRuntime(
            settings.SleepDuration,
            settings.UpstreamUri,
            settings.PassConnectionClose,
            handler,
            invoker,
            outboundClientCertificate);
    }

    public void Dispose()
    {
        HttpInvoker.Dispose();
        _httpHandler.Dispose();
        _outboundClientCertificate?.Dispose();
    }

    private static X509Certificate2 LoadPkcs12CertificateWithFallback(string path, string? password)
    {
        try
        {
            return X509CertificateLoader.LoadPkcs12FromFile(path, password, X509KeyStorageFlags.EphemeralKeySet);
        }
        catch (PlatformNotSupportedException)
        {
            return X509CertificateLoader.LoadPkcs12FromFile(path, password);
        }
    }
}
