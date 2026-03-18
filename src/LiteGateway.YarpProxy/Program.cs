// ─────────────────────────────────────────────────────────────────────────────
// Lite Gateway — YARP Reverse Proxy
// ─────────────────────────────────────────────────────────────────────────────

using System.IO.Compression;
using Microsoft.AspNetCore.ResponseCompression;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

// ── Env var helpers ─────────────────────────────────────────────────────────
static int EnvInt(string key, int defaultValue)
{
    var v = Environment.GetEnvironmentVariable(key);
    return v is not null && int.TryParse(v, out var parsed) ? parsed : defaultValue;
}

static bool EnvBool(string key, bool defaultValue)
{
    var v = Environment.GetEnvironmentVariable(key);
    return v is not null ? v is "1" or "true" or "True" or "TRUE" or "yes" : defaultValue;
}

static int? EnvIntOptional(string key)
{
    var v = Environment.GetEnvironmentVariable(key);
    return v is not null && int.TryParse(v, out var parsed) ? parsed : null;
}

static bool IsCustom(string key) => Environment.GetEnvironmentVariable(key) is not null;
static string Tag(string key) => IsCustom(key) ? "(custom)" : "(default)";

// ── Parse GATEWAY_* performance tuning env vars ─────────────────────────────
// Kestrel (inbound)
var maxConnections            = EnvInt("GATEWAY_MAX_CONNECTIONS", 20_000);
var maxUpgradedConnections    = EnvInt("GATEWAY_MAX_UPGRADED_CONNECTIONS", 20_000);
var keepAliveTimeoutSec       = EnvInt("GATEWAY_KEEPALIVE_TIMEOUT_SEC", 120);
var requestHeaderTimeoutSec   = EnvInt("GATEWAY_REQUEST_HEADER_TIMEOUT_SEC", 30);
var h2MaxStreams              = EnvInt("GATEWAY_H2_MAX_STREAMS", 1024);
var h2InitConnWindowKb        = EnvInt("GATEWAY_H2_INIT_CONNECTION_WINDOW_KB", 1024);
var h2InitStreamWindowKb      = EnvInt("GATEWAY_H2_INIT_STREAM_WINDOW_KB", 768);

// HttpClient (outbound)
var poolLifetimeSec           = EnvInt("GATEWAY_POOL_LIFETIME_SEC", 300);
var poolIdleTimeoutSec        = EnvInt("GATEWAY_POOL_IDLE_TIMEOUT_SEC", 120);
var enableMultiHttp2          = EnvBool("GATEWAY_ENABLE_MULTI_HTTP2", true);

// Compression
var compressionEnabled        = EnvBool("GATEWAY_COMPRESSION", false);

// Thread pool
var minThreads                = EnvIntOptional("GATEWAY_MIN_THREADS");

// ── Parse --config argument ─────────────────────────────────────────────────
var configPath = Path.Combine(Directory.GetCurrentDirectory(), "config.json");
for (var i = 0; i < args.Length; i++)
{
    if (args[i] is "--config" or "-c" && i + 1 < args.Length)
    {
        configPath = Path.GetFullPath(args[i + 1]);
        break;
    }
}

var configFileFound = File.Exists(configPath);

// ── Translate PROXY_HEADER_* env vars → YARP transform env vars ─────────────
// Syntax: PROXY_HEADER_[ACTION_]<HEADER_NAME>[_V]=<value>
//
// Actions: SET_ (default), APPEND_, REMOVE_, RESPONSE_SET_, RESPONSE_APPEND_
// _V suffix: value is the NAME of another env var to read from
//
// Examples:
//   PROXY_HEADER_X_TENANT_ID=customer-42            → Set request X-Tenant-ID: "customer-42"
//   PROXY_HEADER_SET_X_API_KEY_V=SECRET_KEY          → Set request X-Api-Key: value of $SECRET_KEY
//   PROXY_HEADER_RESPONSE_SET_X_VERSION_V=APP_VER    → Set response X-Version: value of $APP_VER
//   PROXY_HEADER_REMOVE_X_INTERNAL=                  → Remove request X-Internal

var headerMappings = new List<(string EnvVar, string Action, string Direction, string HeaderName, string Value, string? SourceEnv)>();
var headerErrors = new List<string>();
var idx = 0;

foreach (var entry in Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>()
             .Where(e => ((string)e.Key).StartsWith("PROXY_HEADER_", StringComparison.Ordinal))
             .OrderBy(e => (string)e.Key))
{
    var envKey = (string)entry.Key;
    var envValue = (string?)entry.Value ?? "";
    var raw = envKey["PROXY_HEADER_".Length..];

    // ── Detect _V suffix (value-from-env-var) ───────────────────────────
    string? sourceEnv = null;
    bool isRef = raw.EndsWith("_V", StringComparison.Ordinal) && raw.Length > 2;
    if (isRef)
    {
        raw = raw[..^2]; // strip _V
        sourceEnv = envValue;
        if (string.IsNullOrEmpty(sourceEnv))
        {
            headerErrors.Add($"  ❌ {envKey}: _V suffix requires a non-empty env var name as value");
            continue;
        }
        var resolved = Environment.GetEnvironmentVariable(sourceEnv);
        if (resolved is null)
        {
            headerErrors.Add($"  ❌ {envKey}: references ${sourceEnv} but that env var is not set");
            continue;
        }
        envValue = resolved;
    }

    // ── Parse action prefix ─────────────────────────────────────────────
    string action, direction, headerName;
    var prefix = $"ReverseProxy__Routes__catch-all__Transforms__{idx}__";

    if (raw.StartsWith("RESPONSE_APPEND_", StringComparison.Ordinal))
    {
        headerName = raw["RESPONSE_APPEND_".Length..];
        action = "Append"; direction = "response";
    }
    else if (raw.StartsWith("RESPONSE_SET_", StringComparison.Ordinal))
    {
        headerName = raw["RESPONSE_SET_".Length..];
        action = "Set"; direction = "response";
    }
    else if (raw.StartsWith("APPEND_", StringComparison.Ordinal))
    {
        headerName = raw["APPEND_".Length..];
        action = "Append"; direction = "request";
    }
    else if (raw.StartsWith("REMOVE_", StringComparison.Ordinal))
    {
        headerName = raw["REMOVE_".Length..];
        action = "Remove"; direction = "request";
    }
    else if (raw.StartsWith("SET_", StringComparison.Ordinal))
    {
        headerName = raw["SET_".Length..];
        action = "Set"; direction = "request";
    }
    else
    {
        // Bare name → request header Set (backward compatible)
        headerName = raw;
        action = "Set"; direction = "request";
    }

    // ── Validate header name ────────────────────────────────────────────
    if (string.IsNullOrEmpty(headerName))
    {
        headerErrors.Add($"  ❌ {envKey}: header name is empty after parsing (check your env var name)");
        continue;
    }

    headerName = headerName.Replace('_', '-');

    // ── Apply YARP transform env vars ───────────────────────────────────
    switch (action)
    {
        case "Set" when direction == "response":
            Environment.SetEnvironmentVariable(prefix + "ResponseHeader", headerName);
            Environment.SetEnvironmentVariable(prefix + "Set", envValue);
            Environment.SetEnvironmentVariable(prefix + "When", "Always");
            break;
        case "Append" when direction == "response":
            Environment.SetEnvironmentVariable(prefix + "ResponseHeader", headerName);
            Environment.SetEnvironmentVariable(prefix + "Append", envValue);
            Environment.SetEnvironmentVariable(prefix + "When", "Always");
            break;
        case "Set":
            Environment.SetEnvironmentVariable(prefix + "RequestHeader", headerName);
            Environment.SetEnvironmentVariable(prefix + "Set", envValue);
            break;
        case "Append":
            Environment.SetEnvironmentVariable(prefix + "RequestHeader", headerName);
            Environment.SetEnvironmentVariable(prefix + "Append", envValue);
            break;
        case "Remove":
            Environment.SetEnvironmentVariable(prefix + "RequestHeaderRemove", headerName);
            break;
    }

    headerMappings.Add((envKey, action, direction, headerName, envValue, sourceEnv));
    idx++;
}

// ── Detect YARP env vars (ReverseProxy__*) ──────────────────────────────────
var yarpEnvVars = Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>()
    .Where(e => ((string)e.Key).StartsWith("ReverseProxy__", StringComparison.Ordinal))
    .OrderBy(e => (string)e.Key)
    .Select(e => ((string)e.Key, (string?)e.Value))
    .ToList();

// ── Startup banner ──────────────────────────────────────────────────────────
Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
Console.WriteLine("║           Lite Gateway — YARP Reverse Proxy                 ║");
Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
Console.WriteLine();

if (configFileFound)
    Console.WriteLine($"  ✅ Config file : {configPath}");
else
    Console.WriteLine($"  ⚠️  Config file : {configPath} (NOT FOUND)");

if (headerMappings.Count > 0)
{
    Console.WriteLine($"  ✅ PROXY_HEADER_* env vars ({headerMappings.Count} detected):");
    foreach (var (envVar, action, direction, header, value, sourceEnv) in headerMappings)
    {
        var from = sourceEnv is not null ? $" (from ${sourceEnv})" : "";
        var display = action == "Remove"
            ? $"{action} {direction} {header}"
            : $"{action} {direction} {header}: \"{value}\"{from}";
        Console.WriteLine($"       {envVar} → {display}");
    }
}
else
{
    Console.WriteLine("  ℹ️  No PROXY_HEADER_* env vars detected");
}

if (headerErrors.Count > 0)
{
    Console.WriteLine();
    Console.WriteLine("  ╔════════════════════════════════════════════════════════╗");
    Console.WriteLine("  ║  FATAL: PROXY_HEADER_* configuration errors           ║");
    Console.WriteLine("  ╚════════════════════════════════════════════════════════╝");
    foreach (var err in headerErrors)
        Console.WriteLine(err);
    Console.WriteLine();
    Console.WriteLine("  Fix the env vars above and restart.");
    Environment.Exit(1);
}

var upstreamEnv = yarpEnvVars
    .FirstOrDefault(e => e.Item1.Contains("Destinations") && e.Item1.Contains("Address"));
if (upstreamEnv != default)
    Console.WriteLine($"  ✅ Upstream (env) : {upstreamEnv.Item2}");

var otherYarpVars = yarpEnvVars
    .Where(e => !e.Item1.Contains("Transforms") && e != upstreamEnv)
    .ToList();
if (otherYarpVars.Count > 0)
{
    Console.WriteLine($"  ✅ YARP env vars ({otherYarpVars.Count} additional):");
    foreach (var (key, val) in otherYarpVars)
        Console.WriteLine($"       {key} = {val}");
}

var listenUrl = Environment.GetEnvironmentVariable("ASPNETCORE_URLS") ?? "http://localhost:8080";
Console.WriteLine($"  🌐 Listen URL  : {listenUrl}");

var otelEndpoint = Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT");
if (!string.IsNullOrEmpty(otelEndpoint))
    Console.WriteLine($"  📡 OpenTelemetry: {otelEndpoint}");
else
    Console.WriteLine("  ℹ️  OpenTelemetry: disabled (set OTEL_EXPORTER_OTLP_ENDPOINT to enable)");

Console.WriteLine();
Console.WriteLine("  ⚡ Performance Tuning");
Console.WriteLine("  ─────────────────────────────────────────────────────────");
Console.WriteLine("  Kestrel (inbound):");
Console.WriteLine($"    MaxConcurrentConnections        = {maxConnections,8}  {Tag("GATEWAY_MAX_CONNECTIONS")}");
Console.WriteLine($"    MaxConcurrentUpgradedConnections = {maxUpgradedConnections,8}  {Tag("GATEWAY_MAX_UPGRADED_CONNECTIONS")}");
Console.WriteLine($"    KeepAliveTimeout                = {keepAliveTimeoutSec,5}s    {Tag("GATEWAY_KEEPALIVE_TIMEOUT_SEC")}");
Console.WriteLine($"    RequestHeadersTimeout           = {requestHeaderTimeoutSec,5}s    {Tag("GATEWAY_REQUEST_HEADER_TIMEOUT_SEC")}");
Console.WriteLine($"    HTTP/2 MaxStreamsPerConnection   = {h2MaxStreams,8}  {Tag("GATEWAY_H2_MAX_STREAMS")}");
Console.WriteLine($"    HTTP/2 InitConnectionWindow      = {h2InitConnWindowKb,5} KB  {Tag("GATEWAY_H2_INIT_CONNECTION_WINDOW_KB")}");
Console.WriteLine($"    HTTP/2 InitStreamWindow          = {h2InitStreamWindowKb,5} KB  {Tag("GATEWAY_H2_INIT_STREAM_WINDOW_KB")}");
Console.WriteLine("  HttpClient (outbound):");
Console.WriteLine($"    PooledConnectionLifetime        = {poolLifetimeSec,5}s    {Tag("GATEWAY_POOL_LIFETIME_SEC")}");
Console.WriteLine($"    PooledConnectionIdleTimeout     = {poolIdleTimeoutSec,5}s    {Tag("GATEWAY_POOL_IDLE_TIMEOUT_SEC")}");
Console.WriteLine($"    EnableMultipleHttp2Connections   = {enableMultiHttp2,-8}  {Tag("GATEWAY_ENABLE_MULTI_HTTP2")}");
Console.WriteLine("  Middleware:");
Console.WriteLine($"    ResponseCompression             = {(compressionEnabled ? "Brotli+Gzip" : "disabled"),-11} {Tag("GATEWAY_COMPRESSION")}");
Console.WriteLine("  Thread Pool:");
if (minThreads.HasValue)
    Console.WriteLine($"    MinWorkerThreads                = {minThreads.Value,8}  {Tag("GATEWAY_MIN_THREADS")}");
else
    Console.WriteLine($"    MinWorkerThreads                = (runtime default)  {Tag("GATEWAY_MIN_THREADS")}");
Console.WriteLine("  ─────────────────────────────────────────────────────────");

Console.WriteLine();

// ── Build ───────────────────────────────────────────────────────────────────
// Apply thread pool tuning before building the host
if (minThreads.HasValue)
    ThreadPool.SetMinThreads(minThreads.Value, minThreads.Value);

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory
});

if (configFileFound)
    builder.Configuration.AddJsonFile(configPath, optional: false, reloadOnChange: true);

builder.Logging.AddFilter("Microsoft.AspNetCore.Hosting.Diagnostics", LogLevel.None);
builder.Logging.AddFilter("Microsoft.Hosting.Lifetime", LogLevel.Warning);

builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Limits.MaxConcurrentConnections = maxConnections;
    options.Limits.MaxConcurrentUpgradedConnections = maxUpgradedConnections;
    options.Limits.MaxRequestBodySize = null;
    options.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(keepAliveTimeoutSec);
    options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(requestHeaderTimeoutSec);
    options.Limits.Http2.MaxStreamsPerConnection = h2MaxStreams;
    options.Limits.Http2.InitialConnectionWindowSize = h2InitConnWindowKb * 1024;
    options.Limits.Http2.InitialStreamWindowSize = h2InitStreamWindowKb * 1024;
    options.Limits.MinRequestBodyDataRate = null;
    options.Limits.MinResponseDataRate = null;
});

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .ConfigureHttpClient((_, handler) =>
    {
        handler.PooledConnectionLifetime = TimeSpan.FromSeconds(poolLifetimeSec);
        handler.PooledConnectionIdleTimeout = TimeSpan.FromSeconds(poolIdleTimeoutSec);
        handler.EnableMultipleHttp2Connections = enableMultiHttp2;
    });

// ── Optional response compression ──────────────────────────────────────────
if (compressionEnabled)
{
    builder.Services.AddResponseCompression(options =>
    {
        options.EnableForHttps = true;
        options.Providers.Add<BrotliCompressionProvider>();
        options.Providers.Add<GzipCompressionProvider>();
    });
    builder.Services.Configure<BrotliCompressionProviderOptions>(options =>
        options.Level = CompressionLevel.Fastest);
    builder.Services.Configure<GzipCompressionProviderOptions>(options =>
        options.Level = CompressionLevel.Fastest);
}

// ── OpenTelemetry (opt-in via OTEL_EXPORTER_OTLP_ENDPOINT) ─────────────────
if (!string.IsNullOrEmpty(otelEndpoint))
{
    var serviceName = Environment.GetEnvironmentVariable("OTEL_SERVICE_NAME") ?? "lite-gateway";

    builder.Services.AddOpenTelemetry()
        .ConfigureResource(r => r.AddService(serviceName))
        .WithTracing(tracing => tracing
            .AddAspNetCoreInstrumentation()
            .AddHttpClientInstrumentation()
            .AddSource("Yarp.ReverseProxy")
            .AddOtlpExporter())
        .WithMetrics(metrics => metrics
            .AddAspNetCoreInstrumentation()
            .AddHttpClientInstrumentation()
            .AddOtlpExporter());

    builder.Logging.AddOpenTelemetry(logging =>
    {
        logging.IncludeScopes = true;
        logging.IncludeFormattedMessage = true;
        logging.AddOtlpExporter();
    });
}

var app = builder.Build();

// ── Post-build validation warnings ──────────────────────────────────────────
var reverseProxySection = app.Configuration.GetSection("ReverseProxy");
var clusters = reverseProxySection.GetSection("Clusters");
var routes = reverseProxySection.GetSection("Routes");

if (!clusters.GetChildren().Any())
    Console.WriteLine("  ⚠️  WARNING: No clusters configured — proxy has no upstream destinations!");
else
{
    foreach (var cluster in clusters.GetChildren())
    {
        var destinations = cluster.GetSection("Destinations");
        foreach (var dest in destinations.GetChildren())
        {
            var address = dest["Address"];
            if (string.IsNullOrEmpty(address))
                Console.WriteLine($"  ⚠️  WARNING: Cluster '{cluster.Key}' destination '{dest.Key}' has no address!");
            else if (address.Contains("localhost:5000"))
                Console.WriteLine($"  ⚠️  WARNING: Cluster '{cluster.Key}' → {address} (default — did you forget to set the upstream?)");
        }
    }
}

if (!routes.GetChildren().Any())
    Console.WriteLine("  ⚠️  WARNING: No routes configured — proxy won't match any requests!");

if (!configFileFound && headerMappings.Count == 0 && yarpEnvVars.Count == 0)
    Console.WriteLine("  ⚠️  WARNING: No config file and no YARP env vars — using built-in defaults only.");

Console.WriteLine();

if (compressionEnabled)
    app.UseResponseCompression();

app.MapReverseProxy();
await app.RunAsync();
