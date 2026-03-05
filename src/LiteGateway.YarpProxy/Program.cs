// ─────────────────────────────────────────────────────────────────────────────
// Lite Gateway — YARP Reverse Proxy
// ─────────────────────────────────────────────────────────────────────────────

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
var headerMappings = new List<(string EnvVar, string HeaderName, string Value)>();
var idx = 0;
foreach (var entry in Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>()
             .Where(e => ((string)e.Key).StartsWith("PROXY_HEADER_", StringComparison.Ordinal))
             .OrderBy(e => (string)e.Key))
{
    var headerName = ((string)entry.Key)["PROXY_HEADER_".Length..].Replace('_', '-');
    var value = (string?)entry.Value ?? "";
    Environment.SetEnvironmentVariable(
        $"ReverseProxy__Routes__catch-all__Transforms__{idx}__RequestHeader", headerName);
    Environment.SetEnvironmentVariable(
        $"ReverseProxy__Routes__catch-all__Transforms__{idx}__Set", value);
    headerMappings.Add(((string)entry.Key, headerName, value));
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
    foreach (var (envVar, header, value) in headerMappings)
        Console.WriteLine($"       {envVar} → {header}: {value}");
}
else
{
    Console.WriteLine("  ℹ️  No PROXY_HEADER_* env vars detected");
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
Console.WriteLine();

// ── Build ───────────────────────────────────────────────────────────────────
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

app.MapReverseProxy();
await app.RunAsync();
