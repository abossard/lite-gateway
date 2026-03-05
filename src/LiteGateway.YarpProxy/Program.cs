// ─────────────────────────────────────────────────────────────────────────────
// Pre-config: translate PROXY_HEADER_* env vars → YARP transform env vars.
// This runs before IConfiguration is built, so YARP picks them up natively.
//
// Example:  PROXY_HEADER_TEST_ID=1234
//   → ReverseProxy__Routes__catch-all__Transforms__0__RequestHeader = TEST-ID
//   → ReverseProxy__Routes__catch-all__Transforms__0__Set           = 1234
// ─────────────────────────────────────────────────────────────────────────────
var idx = 0;
foreach (var entry in Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>()
             .Where(e => ((string)e.Key).StartsWith("PROXY_HEADER_", StringComparison.Ordinal))
             .OrderBy(e => (string)e.Key))
{
    var headerName = ((string)entry.Key)["PROXY_HEADER_".Length..].Replace('_', '-');
    Environment.SetEnvironmentVariable(
        $"ReverseProxy__Routes__catch-all__Transforms__{idx}__RequestHeader", headerName);
    Environment.SetEnvironmentVariable(
        $"ReverseProxy__Routes__catch-all__Transforms__{idx}__Set", (string?)entry.Value);
    idx++;
}

var builder = WebApplication.CreateBuilder(args);

// Layer 1: appsettings.json is loaded by default (baked into image)
// Layer 2: Mounted config file — hot-reloadable, deployment-specific overrides
builder.Configuration.AddJsonFile("/config/yarp.json", optional: true, reloadOnChange: true);
// Layer 3: Environment variables (highest priority, including PROXY_HEADER_* translated above)

builder.Logging.AddFilter("Microsoft.AspNetCore.Hosting.Diagnostics", LogLevel.None);
builder.Logging.AddFilter("Microsoft.Hosting.Lifetime", LogLevel.Warning);

builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Limits.MaxConcurrentConnections = 20_000;
    options.Limits.MaxConcurrentUpgradedConnections = 20_000;
    options.Limits.MaxRequestBodySize = null;
    options.Limits.Http2.MaxStreamsPerConnection = 1_024;
    options.Limits.MinRequestBodyDataRate = null;
    options.Limits.MinResponseDataRate = null;
});

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var app = builder.Build();
app.MapReverseProxy();
await app.RunAsync();
