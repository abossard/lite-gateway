using System.Diagnostics;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace LiteGateway.LoadClient;

internal static class Program
{
    private static readonly ConcurrentDictionary<string, bool> ServerCertificateValidationCache = new(StringComparer.Ordinal);

    public static async Task<int> Main(string[] args)
    {
        if (LoadClientOptions.HasFlag(args, "--help") || LoadClientOptions.HasFlag(args, "-h"))
        {
            PrintHelp();
            return 0;
        }

        LoadClientOptions options;
        try
        {
            options = LoadClientOptions.Parse(args);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Configuration error: {ex.Message}");
            Console.Error.WriteLine("Use --help for usage.");
            return 2;
        }

        try
        {
            if (options.Mode == LoadClientMode.Matrix)
            {
                await RunMatrixAsync(options);
                return 0;
            }

            await RunAsync(options);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Load run failed: {ex.Message}");
            return 1;
        }
    }

    private static async Task<LoadRunResult> RunAsync(LoadClientOptions options, string? runLabel = null, bool showLiveUi = true)
    {
        using var clientCertificate = LoadOptionalClientCertificate(options.ClientCertificatePath, options.ClientCertificatePassword);
        if (options.Profile == LoadClientProfile.ReuseFirst && options.ConnectionClose)
        {
            options = options.With(profile: LoadClientProfile.Balanced);
        }

        using var trustedCaCertificate = string.IsNullOrWhiteSpace(options.CustomCaPath)
            ? null
            : X509CertificateLoader.LoadCertificateFromFile(options.CustomCaPath);

        var metrics = new Metrics();
        using var httpClient = CreateHttpClient(options, clientCertificate, trustedCaCertificate, metrics);
        using var durationCts = new CancellationTokenSource(options.Duration);
        LoadClientTui? tui = null;
        Task? displayTask = null;

        void CancelHandler(object? _, ConsoleCancelEventArgs eventArgs)
        {
            eventArgs.Cancel = true;
            durationCts.Cancel();
        }

        Console.CancelKeyPress += CancelHandler;
        var stopwatch = Stopwatch.StartNew();

        try
        {
            if (showLiveUi)
            {
                tui = LoadClientTui.Create();
                displayTask = DisplayLoopAsync(options, metrics, stopwatch, tui, durationCts.Token);
            }

            var workers = await StartWorkersAsync(httpClient, options, metrics, durationCts.Token).ConfigureAwait(false);
            await Task.WhenAll(workers);
            durationCts.Cancel();
            if (displayTask is not null)
            {
                await displayTask.ConfigureAwait(false);
            }

            var finalSnapshot = metrics.Snapshot(stopwatch.Elapsed);
            if (!showLiveUi)
            {
                var prefix = string.IsNullOrWhiteSpace(runLabel) ? "run" : runLabel;
                Console.WriteLine(
                    $"{prefix}: success={finalSnapshot.Successes} failed={finalSnapshot.Errors} total={finalSnapshot.TotalRequests} " +
                    $"error_pct={ComputeErrorPercentage(finalSnapshot):F2}% success_rps={ComputeSuccessRps(finalSnapshot):F2}");
            }

            return new LoadRunResult(
                runLabel ?? "single",
                options.TargetUri,
                options.Concurrency,
                options.ConnectionClose,
                finalSnapshot.Elapsed,
                finalSnapshot.TotalRequests,
                finalSnapshot.Successes,
                finalSnapshot.Errors,
                ComputeErrorPercentage(finalSnapshot),
                ComputeSuccessRps(finalSnapshot),
                finalSnapshot.Rps,
                finalSnapshot.AvgLatencyMs,
                finalSnapshot.P95Ms);
        }
        finally
        {
            tui?.Dispose();
            Console.CancelKeyPress -= CancelHandler;
        }
    }

    private static async Task RunMatrixAsync(LoadClientOptions baseOptions)
    {
        Console.WriteLine("Running matrix autotune (http/https/mtls x reuse/no-reuse)...");
        var scenarios = new[]
        {
            new MatrixScenario("http-reuse", baseOptions.MatrixHttpUrl, HttpVersion.Version11, ReuseConnections: true, RequiresMtls: false),
            new MatrixScenario("http-no-reuse", baseOptions.MatrixHttpUrl, HttpVersion.Version11, ReuseConnections: false, RequiresMtls: false),
            new MatrixScenario("https-reuse", baseOptions.MatrixHttpsUrl, HttpVersion.Version20, ReuseConnections: true, RequiresMtls: false),
            new MatrixScenario("https-no-reuse", baseOptions.MatrixHttpsUrl, HttpVersion.Version11, ReuseConnections: false, RequiresMtls: false),
            new MatrixScenario("https-mtls-reuse", baseOptions.MatrixMtlsUrl, HttpVersion.Version20, ReuseConnections: true, RequiresMtls: true),
            new MatrixScenario("https-mtls-no-reuse", baseOptions.MatrixMtlsUrl, HttpVersion.Version11, ReuseConnections: false, RequiresMtls: true)
        };

        var results = new List<MatrixScenarioResult>(scenarios.Length);
        foreach (var scenario in scenarios)
        {
            if (scenario.RequiresMtls && string.IsNullOrWhiteSpace(baseOptions.ClientCertificatePath))
            {
                results.Add(MatrixScenarioResult.Skipped(scenario.Name, "missing client certificate"));
                Console.WriteLine($"{scenario.Name}: skipped (missing client certificate)");
                continue;
            }

            var result = await RunAutotuneScenarioAsync(baseOptions, scenario).ConfigureAwait(false);
            results.Add(result);
        }

        PrintMatrixSummary(results);
    }

    private static async Task<Task[]> StartWorkersAsync(
        HttpClient httpClient,
        LoadClientOptions options,
        Metrics metrics,
        CancellationToken cancellationToken)
    {
        var workers = new List<Task>(options.Concurrency);
        var rampPercentPerSecond = options.RampPercentPerSecond;
        var workersPerStep = rampPercentPerSecond <= 0
            ? options.Concurrency
            : Math.Max(1, (int)Math.Ceiling(options.Concurrency * (rampPercentPerSecond / 100d)));

        while (workers.Count < options.Concurrency && !cancellationToken.IsCancellationRequested)
        {
            var stepCount = Math.Min(workersPerStep, options.Concurrency - workers.Count);
            for (var index = 0; index < stepCount; index++)
            {
                workers.Add(WorkerLoopAsync(httpClient, options, metrics, cancellationToken));
            }

            if (workers.Count >= options.Concurrency || workersPerStep >= options.Concurrency)
            {
                break;
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
        }

        return workers.ToArray();
    }

    private static async Task<MatrixScenarioResult> RunAutotuneScenarioAsync(LoadClientOptions baseOptions, MatrixScenario scenario)
    {
        var attempts = new Dictionary<int, LoadRunResult>();
        var bestRun = default(LoadRunResult?);
        int lastGoodConcurrency = 0;
        int firstBadConcurrency = 0;

        var concurrency = baseOptions.AutotuneMinConcurrency;
        while (concurrency <= baseOptions.AutotuneMaxConcurrency)
        {
            var run = await RunScenarioOnceAsync(baseOptions, scenario, concurrency).ConfigureAwait(false);
            attempts[concurrency] = run;
            if (IsHealthy(run, baseOptions.AutotuneMaxErrorPercent))
            {
                lastGoodConcurrency = concurrency;
                if (bestRun is null || run.SuccessRps > bestRun.Value.SuccessRps)
                {
                    bestRun = run;
                }
            }
            else
            {
                firstBadConcurrency = concurrency;
                break;
            }

            if (concurrency >= baseOptions.AutotuneMaxConcurrency)
            {
                break;
            }

            var next = (int)Math.Ceiling(concurrency * baseOptions.AutotuneGrowthFactor);
            if (next <= concurrency)
            {
                next = concurrency + 1;
            }

            concurrency = Math.Min(baseOptions.AutotuneMaxConcurrency, next);
        }

        if (lastGoodConcurrency > 0 && firstBadConcurrency > 0)
        {
            var low = lastGoodConcurrency + 1;
            var high = firstBadConcurrency - 1;
            for (var step = 0; step < baseOptions.AutotuneBinarySearchSteps && low <= high; step++)
            {
                var mid = low + ((high - low) / 2);
                if (attempts.ContainsKey(mid))
                {
                    break;
                }

                var run = await RunScenarioOnceAsync(baseOptions, scenario, mid).ConfigureAwait(false);
                attempts[mid] = run;

                if (IsHealthy(run, baseOptions.AutotuneMaxErrorPercent))
                {
                    lastGoodConcurrency = mid;
                    if (bestRun is null || run.SuccessRps > bestRun.Value.SuccessRps)
                    {
                        bestRun = run;
                    }
                    low = mid + 1;
                }
                else
                {
                    high = mid - 1;
                }
            }
        }

        if (bestRun is null)
        {
            return MatrixScenarioResult.Failed(scenario.Name, attempts.Count, "no healthy run found");
        }

        return MatrixScenarioResult.Success(
            scenario.Name,
            attempts.Count,
            bestRun.Value.Concurrency,
            bestRun.Value.SuccessRps,
            bestRun.Value.ErrorPercentage,
            bestRun.Value.AvgLatencyMs,
            bestRun.Value.P95Ms);
    }

    private static async Task<LoadRunResult> RunScenarioOnceAsync(LoadClientOptions baseOptions, MatrixScenario scenario, int concurrency)
    {
        var scenarioOptions = baseOptions.With(
            targetUri: scenario.Url,
            concurrency: concurrency,
            duration: baseOptions.MatrixRunDuration,
            connectionClose: !scenario.ReuseConnections,
            httpVersion: scenario.RequestHttpVersion,
            mode: LoadClientMode.Single);

        var label = $"{scenario.Name} c={concurrency}";
        return await RunAsync(scenarioOptions, runLabel: label, showLiveUi: false).ConfigureAwait(false);
    }

    private static bool IsHealthy(LoadRunResult run, double maxErrorPercent) =>
        run.TotalRequests > 0 && run.ErrorPercentage <= maxErrorPercent && run.Successes > 0;

    private static void PrintMatrixSummary(IReadOnlyCollection<MatrixScenarioResult> results)
    {
        Console.WriteLine();
        Console.WriteLine("=== Matrix Autotune Summary ===");
        Console.WriteLine("scenario\tstatus\tattempts\tbest_concurrency\tsuccess_rps\terror_pct\tavg_ms\tp95_ms\tnotes");
        foreach (var result in results)
        {
            Console.WriteLine(
                $"{result.ScenarioName}\t{result.Status}\t{result.Attempts}\t{result.BestConcurrency}\t{result.SuccessRps:F2}\t{result.ErrorPercentage:F2}\t{result.AvgLatencyMs:F2}\t{result.P95Ms:F2}\t{result.Notes}");
        }
    }

    private static X509Certificate2? LoadOptionalClientCertificate(string? certificatePath, string? certificatePassword)
    {
        if (string.IsNullOrWhiteSpace(certificatePath))
        {
            return null;
        }

        var certificate = X509CertificateLoader.LoadPkcs12FromFile(certificatePath, certificatePassword);
        if (!certificate.HasPrivateKey)
        {
            certificate.Dispose();
            throw new InvalidOperationException("The client certificate must include a private key.");
        }

        return certificate;
    }

    private static double ComputeErrorPercentage(MetricsSnapshot snapshot)
    {
        if (snapshot.TotalRequests <= 0)
        {
            return 0;
        }

        return (snapshot.Errors * 100d) / snapshot.TotalRequests;
    }

    private static double ComputeSuccessRps(MetricsSnapshot snapshot)
    {
        if (snapshot.Elapsed.TotalSeconds <= 0)
        {
            return 0;
        }

        return snapshot.Successes / snapshot.Elapsed.TotalSeconds;
    }

    private static HttpClient CreateHttpClient(
        LoadClientOptions options,
        X509Certificate2? clientCertificate,
        X509Certificate2? trustedCaCertificate,
        Metrics metrics)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = options.Timeout,
            EnableMultipleHttp2Connections = true,
            MaxConnectionsPerServer = options.Concurrency,
            PooledConnectionIdleTimeout = options.Profile == LoadClientProfile.ReuseFirst
                ? TimeSpan.FromMinutes(10)
                : TimeSpan.FromMinutes(2),
            UseCookies = false
        };

        handler.SslOptions.EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
        if (clientCertificate is not null)
        {
            handler.SslOptions.ClientCertificates = [clientCertificate];
            handler.SslOptions.LocalCertificateSelectionCallback =
                (_, _, _, _, _) => clientCertificate;
        }

        if (trustedCaCertificate is not null)
        {
            handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                ValidateServerCertificate(certificate, trustedCaCertificate);
        }

        if (options.ConnectionClose)
        {
            handler.PooledConnectionLifetime = TimeSpan.Zero;
        }
        else if (options.Profile == LoadClientProfile.ReuseFirst)
        {
            handler.PooledConnectionLifetime = Timeout.InfiniteTimeSpan;
        }

        if (options.TrackOpenedConnections)
        {
            handler.ConnectCallback = async (context, cancellationToken) =>
            {
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp)
                {
                    NoDelay = true
                };

                try
                {
                    await socket.ConnectAsync(context.DnsEndPoint, cancellationToken).ConfigureAwait(false);
                    metrics.RecordOpenedConnection();
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            };
        }

        return new HttpClient(handler, disposeHandler: true)
        {
            Timeout = options.Timeout
        };
    }

    private static async Task WorkerLoopAsync(
        HttpClient httpClient,
        LoadClientOptions options,
        Metrics metrics,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var started = Stopwatch.GetTimestamp();
            metrics.IncrementInflight();

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, options.TargetUri)
                {
                    Version = options.HttpVersion,
                    VersionPolicy = HttpVersionPolicy.RequestVersionExact
                };

                if (options.ConnectionClose && options.HttpVersion == System.Net.HttpVersion.Version11)
                {
                    request.Headers.ConnectionClose = true;
                }

                using var requestTimeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                requestTimeoutCts.CancelAfter(options.MaxRequestTime);

                using var response = await httpClient.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    requestTimeoutCts.Token).ConfigureAwait(false);

                if (response.Content is not null)
                {
                    await response.Content.CopyToAsync(Stream.Null, requestTimeoutCts.Token).ConfigureAwait(false);
                }

                var elapsedTicks = Stopwatch.GetTimestamp() - started;
                var withinMaxRequestTime = elapsedTicks <= options.MaxRequestTimeStopwatchTicks;
                metrics.RecordRequest(elapsedTicks, response.IsSuccessStatusCode && withinMaxRequestTime);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (OperationCanceledException)
            {
                metrics.RecordRequest(Stopwatch.GetTimestamp() - started, isSuccess: false);
            }
            catch
            {
                metrics.RecordRequest(Stopwatch.GetTimestamp() - started, isSuccess: false);
            }
            finally
            {
                metrics.DecrementInflight();
            }
        }
    }

    private static async Task DisplayLoopAsync(
        LoadClientOptions options,
        Metrics metrics,
        Stopwatch stopwatch,
        LoadClientTui tui,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var snapshot = metrics.Snapshot(stopwatch.Elapsed);
            tui.Render(options, snapshot, isFinal: false);

            try
            {
                await Task.Delay(options.RefreshInterval, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
        }

        var finalSnapshot = metrics.Snapshot(stopwatch.Elapsed);
        tui.Render(options, finalSnapshot, isFinal: true);
    }

    private static bool ValidateServerCertificate(X509Certificate? certificate, X509Certificate2 trustedCaCertificate)
    {
        if (certificate is null)
        {
            return false;
        }

        using var serverCertificate = certificate as X509Certificate2 ?? new X509Certificate2(certificate);
        var cacheKey = $"{serverCertificate.Thumbprint}:{serverCertificate.NotAfter.Ticks}:{trustedCaCertificate.Thumbprint}";
        if (ServerCertificateValidationCache.TryGetValue(cacheKey, out var cachedResult))
        {
            return cachedResult;
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(trustedCaCertificate);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.DisableCertificateDownloads = true;

        if (!chain.Build(serverCertificate))
        {
            ServerCertificateValidationCache[cacheKey] = false;
            return false;
        }

        var root = chain.ChainElements.Count == 0 ? null : chain.ChainElements[^1].Certificate;
        var isValid = root is not null &&
                      string.Equals(root.Thumbprint, trustedCaCertificate.Thumbprint, StringComparison.OrdinalIgnoreCase);
        ServerCertificateValidationCache[cacheKey] = isValid;
        return isValid;
    }

    private static void PrintHelp()
    {
        Console.WriteLine("Usage: LiteGateway.LoadClient [options]");
        Console.WriteLine("Options:");
        Console.WriteLine("  --mode <single|matrix>             Run one target or full matrix (default: matrix when --url is omitted)");
        Console.WriteLine("  --url <https-url>                  Target URL (env: LITEGATEWAY_LOADCLIENT_URL)");
        Console.WriteLine("  --cert-pfx <path>                  Client PFX path (env: LITEGATEWAY_LOADCLIENT_CERT_PFX)");
        Console.WriteLine("  --cert-password <value>            Client PFX password (env: LITEGATEWAY_LOADCLIENT_CERT_PASSWORD)");
        Console.WriteLine("  --custom-ca <path>                 Optional custom CA cert (env: LITEGATEWAY_LOADCLIENT_CUSTOM_CA)");
        Console.WriteLine("  --concurrency <int>                Workers, default 64 (env: LITEGATEWAY_LOADCLIENT_CONCURRENCY)");
        Console.WriteLine("  --duration <seconds|hh:mm:ss>      Test duration, default 60s (env: LITEGATEWAY_LOADCLIENT_DURATION)");
        Console.WriteLine("  --timeout <seconds|hh:mm:ss>       Request timeout, default 30s (env: LITEGATEWAY_LOADCLIENT_TIMEOUT)");
        Console.WriteLine("  --max-request-time <seconds|hh:mm:ss>  Mark request as error after this time, default 10s (env: LITEGATEWAY_LOADCLIENT_MAX_REQUEST_TIME)");
        Console.WriteLine("  --ramp-percent-per-second <0-100>  Add this % of target workers each second, default 10 (env: LITEGATEWAY_LOADCLIENT_RAMP_PERCENT_PER_SECOND)");
        Console.WriteLine("  --refresh-interval <seconds|hh:mm:ss>  UI refresh, default 1s (env: LITEGATEWAY_LOADCLIENT_REFRESH_INTERVAL)");
        Console.WriteLine("  --http-version <1.1|2|3>           HTTP version, default 2 (env: LITEGATEWAY_LOADCLIENT_HTTP_VERSION)");
        Console.WriteLine("  --connection-close                 Send Connection: close (requires --http-version 1.1)");
        Console.WriteLine("  --profile <balanced|reuse-first>   HTTP handler profile (default: reuse-first)");
        Console.WriteLine("  --track-opened-connections <bool>  Track opened TCP sockets via ConnectCallback (default: false)");
        Console.WriteLine("  --matrix-http-url <http-url>       Matrix HTTP endpoint (default: http://localhost:8080/)");
        Console.WriteLine("  --matrix-https-url <https-url>     Matrix HTTPS endpoint (default: https://localhost:8443/)");
        Console.WriteLine("  --matrix-mtls-url <https-url>      Matrix mTLS endpoint (default: https://localhost:9443/)");
        Console.WriteLine("  --matrix-run-duration <sec|hh:mm:ss>  Duration per matrix attempt (default: 20s)");
        Console.WriteLine("  --autotune-min-concurrency <int>   Matrix autotune min concurrency (default: 256)");
        Console.WriteLine("  --autotune-max-concurrency <int>   Matrix autotune max concurrency (default: 8192)");
        Console.WriteLine("  --autotune-growth-factor <double>  Matrix autotune growth factor (default: 2.0)");
        Console.WriteLine("  --autotune-max-error-pct <double>  Max error % for healthy run (default: 2.0)");
        Console.WriteLine("  --autotune-binary-steps <int>      Binary search steps after first failure (default: 5)");
        Console.WriteLine("  live TUI                           Auto-enabled on interactive terminal (RPS/p95 graphs + histogram)");
        Console.WriteLine("  --help                             Show this help");
    }
}

internal sealed class LoadClientOptions
{
    public required LoadClientMode Mode { get; init; }
    public required Uri TargetUri { get; init; }
    public required string? ClientCertificatePath { get; init; }
    public required string? ClientCertificatePassword { get; init; }
    public string? CustomCaPath { get; init; }
    public required int Concurrency { get; init; }
    public required TimeSpan Duration { get; init; }
    public required TimeSpan Timeout { get; init; }
    public required TimeSpan MaxRequestTime { get; init; }
    public required long MaxRequestTimeStopwatchTicks { get; init; }
    public required double RampPercentPerSecond { get; init; }
    public required TimeSpan RefreshInterval { get; init; }
    public required Version HttpVersion { get; init; }
    public required bool ConnectionClose { get; init; }
    public required LoadClientProfile Profile { get; init; }
    public required bool TrackOpenedConnections { get; init; }
    public required Uri MatrixHttpUrl { get; init; }
    public required Uri MatrixHttpsUrl { get; init; }
    public required Uri MatrixMtlsUrl { get; init; }
    public required TimeSpan MatrixRunDuration { get; init; }
    public required int AutotuneMinConcurrency { get; init; }
    public required int AutotuneMaxConcurrency { get; init; }
    public required double AutotuneGrowthFactor { get; init; }
    public required double AutotuneMaxErrorPercent { get; init; }
    public required int AutotuneBinarySearchSteps { get; init; }

    public static LoadClientOptions Parse(string[] args)
    {
        var targetUrlRaw = ReadOptional(args, "--url", "URL");
        var mode = ParseMode(ReadOptional(args, "--mode", "MODE"), hasTargetUrl: !string.IsNullOrWhiteSpace(targetUrlRaw));
        var targetUri = mode == LoadClientMode.Single
            ? ParseEndpointUri(targetUrlRaw, "--url", requireHttps: false)
            : ParseEndpointUri(ReadOptional(args, "--matrix-https-url", "MATRIX_HTTPS_URL") ?? "https://localhost:8443/", "--matrix-https-url", requireHttps: true);

        var clientCertificatePathRaw = ReadOptional(args, "--cert-pfx", "CERT_PFX") ??
                                       Environment.GetEnvironmentVariable("CLIENT_PFX");
        var clientCertificatePath = string.IsNullOrWhiteSpace(clientCertificatePathRaw)
            ? null
            : ResolveRequiredFilePath(clientCertificatePathRaw, "--cert-pfx");
        var clientCertificatePassword = ReadOptional(args, "--cert-password", "CERT_PASSWORD") ??
                                        Environment.GetEnvironmentVariable("CLIENT_PFX_PASSWORD");

        var customCaPath = ReadOptional(args, "--custom-ca", "CUSTOM_CA") ??
                           Environment.GetEnvironmentVariable("CLIENT_CA_CERT");
        if (!string.IsNullOrWhiteSpace(customCaPath))
        {
            customCaPath = ResolveRequiredFilePath(customCaPath, "--custom-ca");
        }

        var profile = ParseProfile(ReadOptional(args, "--profile", "PROFILE"));
        var trackOpenedConnections = ParseBool(
            ReadOptional(args, "--track-opened-connections", "TRACK_OPENED_CONNECTIONS"),
            fallback: false);
        var concurrency = ParseInt(ReadOptional(args, "--concurrency", "CONCURRENCY"), 64, 1, 1_000_000, "--concurrency");
        var duration = ParseTimeSpan(ReadOptional(args, "--duration", "DURATION"), TimeSpan.FromSeconds(60), "--duration");
        var timeout = ParseTimeSpan(ReadOptional(args, "--timeout", "TIMEOUT"), TimeSpan.FromSeconds(30), "--timeout");
        var maxRequestTime = ParseTimeSpan(
            ReadOptional(args, "--max-request-time", "MAX_REQUEST_TIME"),
            TimeSpan.FromSeconds(10),
            "--max-request-time");
        var rampPercentPerSecond = ParsePercent(
            ReadOptional(args, "--ramp-percent-per-second", "RAMP_PERCENT_PER_SECOND"),
            10,
            "--ramp-percent-per-second");
        var matrixHttpUrl = ParseEndpointUri(
            ReadOptional(args, "--matrix-http-url", "MATRIX_HTTP_URL") ?? "http://localhost:8080/",
            "--matrix-http-url",
            requireHttps: false,
            allowedScheme: Uri.UriSchemeHttp);
        var matrixHttpsUrl = ParseEndpointUri(
            ReadOptional(args, "--matrix-https-url", "MATRIX_HTTPS_URL") ?? "https://localhost:8443/",
            "--matrix-https-url",
            requireHttps: true);
        var matrixMtlsUrl = ParseEndpointUri(
            ReadOptional(args, "--matrix-mtls-url", "MATRIX_MTLS_URL") ?? "https://localhost:9443/",
            "--matrix-mtls-url",
            requireHttps: true);
        var matrixRunDuration = ParseTimeSpan(
            ReadOptional(args, "--matrix-run-duration", "MATRIX_RUN_DURATION"),
            TimeSpan.FromSeconds(20),
            "--matrix-run-duration");
        var autotuneMinConcurrency = ParseInt(
            ReadOptional(args, "--autotune-min-concurrency", "AUTOTUNE_MIN_CONCURRENCY"),
            256,
            1,
            1_000_000,
            "--autotune-min-concurrency");
        var autotuneMaxConcurrency = ParseInt(
            ReadOptional(args, "--autotune-max-concurrency", "AUTOTUNE_MAX_CONCURRENCY"),
            8192,
            autotuneMinConcurrency,
            1_000_000,
            "--autotune-max-concurrency");
        var autotuneGrowthFactor = ParseDouble(
            ReadOptional(args, "--autotune-growth-factor", "AUTOTUNE_GROWTH_FACTOR"),
            2.0,
            1.1,
            10.0,
            "--autotune-growth-factor");
        var autotuneMaxErrorPercent = ParseDouble(
            ReadOptional(args, "--autotune-max-error-pct", "AUTOTUNE_MAX_ERROR_PCT"),
            2.0,
            0.0,
            100.0,
            "--autotune-max-error-pct");
        var autotuneBinarySearchSteps = ParseInt(
            ReadOptional(args, "--autotune-binary-steps", "AUTOTUNE_BINARY_STEPS"),
            5,
            0,
            20,
            "--autotune-binary-steps");
        var refreshInterval = ParseTimeSpan(
            ReadOptional(args, "--refresh-interval", "REFRESH_INTERVAL"),
            TimeSpan.FromSeconds(1),
            "--refresh-interval");
        var httpVersion = ParseHttpVersion(ReadOptional(args, "--http-version", "HTTP_VERSION"));
        var connectionClose = ParseConnectionClose(args);
        if (connectionClose && httpVersion != System.Net.HttpVersion.Version11)
        {
            throw new InvalidOperationException("--connection-close requires --http-version 1.1.");
        }

        return new LoadClientOptions
        {
            Mode = mode,
            TargetUri = targetUri,
            ClientCertificatePath = clientCertificatePath,
            ClientCertificatePassword = clientCertificatePassword,
            CustomCaPath = customCaPath,
            Concurrency = concurrency,
            Duration = duration,
            Timeout = timeout,
            MaxRequestTime = maxRequestTime,
            MaxRequestTimeStopwatchTicks = ToStopwatchTicks(maxRequestTime),
            RampPercentPerSecond = rampPercentPerSecond,
            RefreshInterval = refreshInterval,
            HttpVersion = httpVersion,
            ConnectionClose = connectionClose,
            Profile = profile,
            TrackOpenedConnections = trackOpenedConnections,
            MatrixHttpUrl = matrixHttpUrl,
            MatrixHttpsUrl = matrixHttpsUrl,
            MatrixMtlsUrl = matrixMtlsUrl,
            MatrixRunDuration = matrixRunDuration,
            AutotuneMinConcurrency = autotuneMinConcurrency,
            AutotuneMaxConcurrency = autotuneMaxConcurrency,
            AutotuneGrowthFactor = autotuneGrowthFactor,
            AutotuneMaxErrorPercent = autotuneMaxErrorPercent,
            AutotuneBinarySearchSteps = autotuneBinarySearchSteps
        };
    }

    public static bool HasFlag(string[] args, string flagName)
    {
        foreach (var arg in args)
        {
            if (string.Equals(arg, flagName, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ParseConnectionClose(string[] args)
    {
        if (HasFlag(args, "--connection-close"))
        {
            return true;
        }

        var fromArgs = ReadArgumentValue(args, "--connection-close");
        if (!string.IsNullOrWhiteSpace(fromArgs))
        {
            return ParseBool(fromArgs, "--connection-close");
        }

        var fromEnvironment = Environment.GetEnvironmentVariable("LITEGATEWAY_LOADCLIENT_CONNECTION_CLOSE");
        return ParseBool(fromEnvironment, fallback: false);
    }

    private static Version ParseHttpVersion(string? rawValue)
    {
        var value = string.IsNullOrWhiteSpace(rawValue) ? "2" : rawValue.Trim();
        return value switch
        {
            "1" or "1.1" => System.Net.HttpVersion.Version11,
            "2" or "2.0" => System.Net.HttpVersion.Version20,
            "3" or "3.0" => System.Net.HttpVersion.Version30,
            _ => throw new InvalidOperationException("--http-version must be 1.1, 2, or 3.")
        };
    }

    private static LoadClientMode ParseMode(string? rawValue, bool hasTargetUrl)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return hasTargetUrl ? LoadClientMode.Single : LoadClientMode.Matrix;
        }

        return rawValue.Trim().ToLowerInvariant() switch
        {
            "single" => LoadClientMode.Single,
            "matrix" => LoadClientMode.Matrix,
            _ => throw new InvalidOperationException("--mode must be single or matrix.")
        };
    }

    private static LoadClientProfile ParseProfile(string? rawValue)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return LoadClientProfile.ReuseFirst;
        }

        return rawValue.Trim().ToLowerInvariant() switch
        {
            "balanced" => LoadClientProfile.Balanced,
            "reuse-first" => LoadClientProfile.ReuseFirst,
            _ => throw new InvalidOperationException("--profile must be balanced or reuse-first.")
        };
    }

    private static Uri ParseEndpointUri(
        string? rawValue,
        string settingName,
        bool requireHttps,
        string? allowedScheme = null)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            throw new InvalidOperationException($"{settingName} is required.");
        }

        if (!Uri.TryCreate(rawValue, UriKind.Absolute, out var uri))
        {
            throw new InvalidOperationException($"{settingName} must be an absolute URL.");
        }

        if (requireHttps && !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"{settingName} must be an https URL.");
        }

        if (!requireHttps && allowedScheme is not null &&
            !string.Equals(uri.Scheme, allowedScheme, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"{settingName} must use {allowedScheme}.");
        }

        if (!requireHttps && allowedScheme is null &&
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"{settingName} must be an http or https URL.");
        }

        return uri;
    }

    private static TimeSpan ParseTimeSpan(string? rawValue, TimeSpan fallback, string settingName)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return fallback;
        }

        if (int.TryParse(rawValue, out var seconds) && seconds > 0)
        {
            return TimeSpan.FromSeconds(seconds);
        }

        if (TimeSpan.TryParse(rawValue, out var timeSpan) && timeSpan > TimeSpan.Zero)
        {
            return timeSpan;
        }

        throw new InvalidOperationException($"{settingName} must be a positive integer number of seconds or a positive TimeSpan.");
    }

    private static long ToStopwatchTicks(TimeSpan value)
    {
        var ticks = value.TotalSeconds * Stopwatch.Frequency;
        if (ticks < 1)
        {
            return 1;
        }

        if (ticks > long.MaxValue)
        {
            return long.MaxValue;
        }

        return (long)ticks;
    }

    private static double ParsePercent(string? rawValue, double fallback, string settingName)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return fallback;
        }

        if (double.TryParse(rawValue, out var parsedValue) && parsedValue >= 0 && parsedValue <= 100)
        {
            return parsedValue;
        }

        throw new InvalidOperationException($"{settingName} must be between 0 and 100.");
    }

    private static double ParseDouble(string? rawValue, double fallback, double min, double max, string settingName)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return fallback;
        }

        if (double.TryParse(rawValue, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsedValue) &&
            parsedValue >= min &&
            parsedValue <= max)
        {
            return parsedValue;
        }

        throw new InvalidOperationException($"{settingName} must be between {min} and {max}.");
    }

    private static int ParseInt(string? rawValue, int fallback, int min, int max, string settingName)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return fallback;
        }

        if (int.TryParse(rawValue, out var parsedValue) && parsedValue >= min && parsedValue <= max)
        {
            return parsedValue;
        }

        throw new InvalidOperationException($"{settingName} must be between {min} and {max}.");
    }

    private static bool ParseBool(string? rawValue, bool fallback)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return fallback;
        }

        return ParseBool(rawValue, "boolean setting");
    }

    private static bool ParseBool(string rawValue, string settingName)
    {
        if (bool.TryParse(rawValue, out var parsedValue))
        {
            return parsedValue;
        }

        if (string.Equals(rawValue, "1", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(rawValue, "yes", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (string.Equals(rawValue, "0", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(rawValue, "no", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        throw new InvalidOperationException($"{settingName} must be true/false.");
    }

    private static string ReadRequired(string[] args, string argumentName, string environmentNameSuffix)
    {
        var value = ReadOptional(args, argumentName, environmentNameSuffix);
        if (!string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        throw new InvalidOperationException($"{argumentName} or LITEGATEWAY_LOADCLIENT_{environmentNameSuffix} is required.");
    }

    private static string? ReadOptional(string[] args, string argumentName, string environmentNameSuffix)
    {
        var fromArgs = ReadArgumentValue(args, argumentName);
        if (!string.IsNullOrWhiteSpace(fromArgs))
        {
            return fromArgs;
        }

        return Environment.GetEnvironmentVariable($"LITEGATEWAY_LOADCLIENT_{environmentNameSuffix}");
    }

    private static string? ReadArgumentValue(string[] args, string argumentName)
    {
        var equalsPrefix = $"{argumentName}=";
        for (var index = 0; index < args.Length; index++)
        {
            var argument = args[index];
            if (argument.StartsWith(equalsPrefix, StringComparison.OrdinalIgnoreCase))
            {
                return argument[equalsPrefix.Length..];
            }

            if (!string.Equals(argument, argumentName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (index + 1 >= args.Length)
            {
                throw new InvalidOperationException($"{argumentName} expects a value.");
            }

            return args[index + 1];
        }

        return null;
    }

    private static string ResolveRequiredFilePath(string path, string settingName)
    {
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            throw new InvalidOperationException($"{settingName} file was not found at '{fullPath}'.");
        }

        return fullPath;
    }

    public LoadClientOptions With(
        Uri? targetUri = null,
        int? concurrency = null,
        TimeSpan? duration = null,
        bool? connectionClose = null,
        LoadClientMode? mode = null,
        LoadClientProfile? profile = null,
        Version? httpVersion = null)
    {
        return new LoadClientOptions
        {
            Mode = mode ?? Mode,
            TargetUri = targetUri ?? TargetUri,
            ClientCertificatePath = ClientCertificatePath,
            ClientCertificatePassword = ClientCertificatePassword,
            CustomCaPath = CustomCaPath,
            Concurrency = concurrency ?? Concurrency,
            Duration = duration ?? Duration,
            Timeout = Timeout,
            MaxRequestTime = MaxRequestTime,
            MaxRequestTimeStopwatchTicks = MaxRequestTimeStopwatchTicks,
            RampPercentPerSecond = RampPercentPerSecond,
            RefreshInterval = RefreshInterval,
            HttpVersion = httpVersion ?? HttpVersion,
            ConnectionClose = connectionClose ?? ConnectionClose,
            Profile = profile ?? Profile,
            TrackOpenedConnections = TrackOpenedConnections,
            MatrixHttpUrl = MatrixHttpUrl,
            MatrixHttpsUrl = MatrixHttpsUrl,
            MatrixMtlsUrl = MatrixMtlsUrl,
            MatrixRunDuration = MatrixRunDuration,
            AutotuneMinConcurrency = AutotuneMinConcurrency,
            AutotuneMaxConcurrency = AutotuneMaxConcurrency,
            AutotuneGrowthFactor = AutotuneGrowthFactor,
            AutotuneMaxErrorPercent = AutotuneMaxErrorPercent,
            AutotuneBinarySearchSteps = AutotuneBinarySearchSteps
        };
    }
}

internal sealed class Metrics
{
    private long _inflight;
    private long _openedConnections;
    private long _totalRequests;
    private long _successfulRequests;
    private long _failedRequests;
    private long _totalLatencyTicks;
    private readonly LatencyHistogram _histogram = new();

    public void IncrementInflight() => Interlocked.Increment(ref _inflight);

    public void DecrementInflight() => Interlocked.Decrement(ref _inflight);

    public void RecordOpenedConnection() => Interlocked.Increment(ref _openedConnections);

    public void RecordRequest(long latencyTicks, bool isSuccess)
    {
        Interlocked.Increment(ref _totalRequests);
        Interlocked.Add(ref _totalLatencyTicks, latencyTicks);
        _histogram.Record(latencyTicks);

        if (isSuccess)
        {
            Interlocked.Increment(ref _successfulRequests);
            return;
        }

        Interlocked.Increment(ref _failedRequests);
    }

    public MetricsSnapshot Snapshot(TimeSpan elapsed)
    {
        var totalRequests = Volatile.Read(ref _totalRequests);
        var totalLatencyTicks = Volatile.Read(ref _totalLatencyTicks);
        var elapsedSeconds = Math.Max(elapsed.TotalSeconds, 0.000001);
        var rps = totalRequests / elapsedSeconds;
        var averageLatencyMs = totalRequests == 0
            ? 0
            : totalLatencyTicks * 1000d / Stopwatch.Frequency / totalRequests;

        return new MetricsSnapshot(
            elapsed,
            Volatile.Read(ref _inflight),
            Volatile.Read(ref _openedConnections),
            totalRequests,
            Volatile.Read(ref _successfulRequests),
            Volatile.Read(ref _failedRequests),
            rps,
            averageLatencyMs,
            _histogram.PercentileMilliseconds(0.50),
            _histogram.PercentileMilliseconds(0.95),
            _histogram.PercentileMilliseconds(0.99));
    }

    public LatencyHistogramSnapshot LatencyHistogramSnapshot() => _histogram.Snapshot();
}

internal sealed class LatencyHistogram
{
    private static readonly long[] BucketUpperBoundsTicks =
    [
        MsToTicks(1), MsToTicks(2), MsToTicks(3), MsToTicks(5), MsToTicks(8),
        MsToTicks(10), MsToTicks(15), MsToTicks(20), MsToTicks(30), MsToTicks(40),
        MsToTicks(50), MsToTicks(75), MsToTicks(100), MsToTicks(150), MsToTicks(200),
        MsToTicks(300), MsToTicks(400), MsToTicks(500), MsToTicks(750), MsToTicks(1000),
        MsToTicks(1500), MsToTicks(2000), MsToTicks(3000), MsToTicks(5000), MsToTicks(7500),
        MsToTicks(10000), MsToTicks(15000), MsToTicks(20000), MsToTicks(30000), MsToTicks(60000)
    ];

    private readonly long[] _bucketCounts = new long[BucketUpperBoundsTicks.Length + 1];

    public void Record(long latencyTicks)
    {
        var bucketIndex = FindBucket(latencyTicks);
        Interlocked.Increment(ref _bucketCounts[bucketIndex]);
    }

    public double PercentileMilliseconds(double percentile)
    {
        long total = 0;
        for (var index = 0; index < _bucketCounts.Length; index++)
        {
            total += Volatile.Read(ref _bucketCounts[index]);
        }

        if (total == 0)
        {
            return 0;
        }

        var target = (long)Math.Ceiling(total * percentile);
        long running = 0;

        for (var index = 0; index < _bucketCounts.Length; index++)
        {
            running += Volatile.Read(ref _bucketCounts[index]);
            if (running < target)
            {
                continue;
            }

            var upperBoundTicks = index < BucketUpperBoundsTicks.Length
                ? BucketUpperBoundsTicks[index]
                : BucketUpperBoundsTicks[^1];
            return upperBoundTicks * 1000d / Stopwatch.Frequency;
        }

        return BucketUpperBoundsTicks[^1] * 1000d / Stopwatch.Frequency;
    }

    public LatencyHistogramSnapshot Snapshot()
    {
        var snapshotCounts = new long[_bucketCounts.Length];
        long total = 0;
        for (var index = 0; index < _bucketCounts.Length; index++)
        {
            var count = Volatile.Read(ref _bucketCounts[index]);
            snapshotCounts[index] = count;
            total += count;
        }

        var cumulativeLe1s = CountUpToTicks(MsToTicks(1000), snapshotCounts);
        var cumulativeLe2s = CountUpToTicks(MsToTicks(2000), snapshotCounts);
        var cumulativeLe5s = CountUpToTicks(MsToTicks(5000), snapshotCounts);
        var cumulativeLe10s = CountUpToTicks(MsToTicks(10000), snapshotCounts);
        var cumulativeLe20s = CountUpToTicks(MsToTicks(20000), snapshotCounts);

        return new LatencyHistogramSnapshot(
            total,
            cumulativeLe1s,
            Math.Max(0, cumulativeLe2s - cumulativeLe1s),
            Math.Max(0, cumulativeLe5s - cumulativeLe2s),
            Math.Max(0, cumulativeLe10s - cumulativeLe5s),
            Math.Max(0, cumulativeLe20s - cumulativeLe10s),
            Math.Max(0, total - cumulativeLe20s));
    }

    private static int FindBucket(long latencyTicks)
    {
        var low = 0;
        var high = BucketUpperBoundsTicks.Length - 1;

        while (low <= high)
        {
            var mid = low + ((high - low) / 2);
            if (latencyTicks <= BucketUpperBoundsTicks[mid])
            {
                high = mid - 1;
            }
            else
            {
                low = mid + 1;
            }
        }

        return low;
    }

    private static long CountUpToTicks(long limitTicks, long[] snapshotCounts)
    {
        long total = 0;
        for (var index = 0; index < snapshotCounts.Length; index++)
        {
            if (index < BucketUpperBoundsTicks.Length && BucketUpperBoundsTicks[index] > limitTicks)
            {
                break;
            }

            total += snapshotCounts[index];
        }

        return total;
    }

    private static long MsToTicks(int milliseconds) => milliseconds * Stopwatch.Frequency / 1000;
}

internal readonly record struct MetricsSnapshot(
    TimeSpan Elapsed,
    long Inflight,
    long OpenedConnections,
    long TotalRequests,
    long Successes,
    long Errors,
    double Rps,
    double AvgLatencyMs,
    double P50Ms,
    double P95Ms,
    double P99Ms);

internal readonly record struct LatencyHistogramSnapshot(
    long Total,
    long Le1s,
    long Between1sAnd2s,
    long Between2sAnd5s,
    long Between5sAnd10s,
    long Between10sAnd20s,
    long Gt20s);

internal readonly record struct LoadRunResult(
    string Label,
    Uri TargetUri,
    int Concurrency,
    bool ConnectionClose,
    TimeSpan Elapsed,
    long TotalRequests,
    long Successes,
    long Errors,
    double ErrorPercentage,
    double SuccessRps,
    double TotalRps,
    double AvgLatencyMs,
    double P95Ms);

internal readonly record struct MatrixScenario(
    string Name,
    Uri Url,
    Version RequestHttpVersion,
    bool ReuseConnections,
    bool RequiresMtls);

internal readonly record struct MatrixScenarioResult(
    string ScenarioName,
    string Status,
    int Attempts,
    int BestConcurrency,
    double SuccessRps,
    double ErrorPercentage,
    double AvgLatencyMs,
    double P95Ms,
    string Notes)
{
    public static MatrixScenarioResult Success(
        string scenarioName,
        int attempts,
        int bestConcurrency,
        double successRps,
        double errorPercentage,
        double avgLatencyMs,
        double p95Ms) =>
        new(scenarioName, "ok", attempts, bestConcurrency, successRps, errorPercentage, avgLatencyMs, p95Ms, "");

    public static MatrixScenarioResult Failed(string scenarioName, int attempts, string notes) =>
        new(scenarioName, "failed", attempts, 0, 0, 100, 0, 0, notes);

    public static MatrixScenarioResult Skipped(string scenarioName, string notes) =>
        new(scenarioName, "skipped", 0, 0, 0, 0, 0, 0, notes);
}

internal enum LoadClientMode
{
    Single,
    Matrix
}

internal enum LoadClientProfile
{
    Balanced,
    ReuseFirst
}

internal sealed class LoadClientTui : IDisposable
{
    private const string SparklineBlocks = "▁▂▃▄▅▆▇█";
    private readonly bool _interactive;
    private readonly StringBuilder _buffer = new(8192);
    private readonly RollingSeries _rpsSeries;
    private readonly RollingSeries _p95Series;
    private bool _firstRender = true;
    private bool _hasBaseline;
    private long _lastTotalRequests;
    private TimeSpan _lastElapsed;
    private double _peakInstantRps;

    private LoadClientTui(bool interactive)
    {
        _interactive = interactive;
        var width = GetTerminalWidth();
        var seriesSize = Math.Max(32, width - 20);
        _rpsSeries = new RollingSeries(seriesSize);
        _p95Series = new RollingSeries(seriesSize);

        if (_interactive)
        {
            Console.Write("\u001b[?25l");
        }
    }

    public static LoadClientTui Create() => new(interactive: !Console.IsOutputRedirected);

    public void Render(LoadClientOptions options, MetricsSnapshot snapshot, bool isFinal)
    {
        var instantRps = CalculateInstantRps(snapshot);
        _peakInstantRps = Math.Max(_peakInstantRps, instantRps);
        _rpsSeries.Add(instantRps);
        _p95Series.Add(snapshot.P95Ms);

        if (_interactive)
        {
            RenderInteractive(options, snapshot, instantRps, isFinal);
            return;
        }

        RenderPlain(options, snapshot, instantRps, isFinal);
    }

    public void Dispose()
    {
        if (_interactive)
        {
            Console.Write("\u001b[?25h");
        }
    }

    private double CalculateInstantRps(MetricsSnapshot snapshot)
    {
        if (!_hasBaseline)
        {
            _hasBaseline = true;
            _lastTotalRequests = snapshot.TotalRequests;
            _lastElapsed = snapshot.Elapsed;
            return snapshot.Rps;
        }

        var deltaRequests = snapshot.TotalRequests - _lastTotalRequests;
        var deltaSeconds = (snapshot.Elapsed - _lastElapsed).TotalSeconds;
        _lastTotalRequests = snapshot.TotalRequests;
        _lastElapsed = snapshot.Elapsed;

        if (deltaRequests <= 0 || deltaSeconds <= 0)
        {
            return 0;
        }

        return deltaRequests / deltaSeconds;
    }

    private void RenderPlain(LoadClientOptions options, MetricsSnapshot snapshot, double instantRps, bool isFinal)
    {
        var currentRpsBar = BuildValueBar(instantRps, Math.Max(_peakInstantRps, 1), 20);
        Console.WriteLine("LiteGateway.LoadClient");
        Console.WriteLine(
            $"target={options.TargetUri} http={options.HttpVersion} concurrency={options.Concurrency} close={options.ConnectionClose} max_req={options.MaxRequestTime} ramp={options.RampPercentPerSecond:F1}%/s");
        Console.WriteLine(
            $"elapsed={snapshot.Elapsed:hh\\:mm\\:ss} inflight={snapshot.Inflight} opened_tcp={snapshot.OpenedConnections}");
        Console.WriteLine(
            $"total={snapshot.TotalRequests} success={snapshot.Successes} errors={snapshot.Errors} rps_avg={snapshot.Rps:F1} rps_inst={instantRps:F1} rps_peak={_peakInstantRps:F1}");
        Console.WriteLine($"rps_now_visual={currentRpsBar}");
        Console.WriteLine(
            $"avg={snapshot.AvgLatencyMs:F2}ms p50={snapshot.P50Ms:F2}ms p95={snapshot.P95Ms:F2}ms p99={snapshot.P99Ms:F2}ms");

        if (isFinal)
        {
            Console.WriteLine(BuildFinalSummary(snapshot));
            Console.WriteLine("completed");
        }
    }

    private void RenderInteractive(LoadClientOptions options, MetricsSnapshot snapshot, double instantRps, bool isFinal)
    {
        var width = GetTerminalWidth();
        var graphWidth = Math.Clamp(width - 22, 24, 220);
        var rpsData = _rpsSeries.Snapshot();
        var p95Data = _p95Series.Snapshot();
        var rpsGraph = BuildSparkline(rpsData, graphWidth);
        var p95Graph = BuildSparkline(p95Data, graphWidth);
        var progressBar = BuildProgressBar(snapshot.Elapsed, options.Duration, Math.Clamp(width - 42, 16, 80));
        var currentRpsBar = BuildValueBar(instantRps, Math.Max(_peakInstantRps, 1), Math.Clamp(width - 44, 18, 96));

        _buffer.Clear();
        if (_firstRender)
        {
            _buffer.Append("\u001b[2J");
            _firstRender = false;
        }

        _buffer.Append("\u001b[H");
        _buffer.AppendLine("LiteGateway.LoadClient - Live TUI Dashboard (Ctrl+C to stop)");
        _buffer.Append("Target: ").Append(options.TargetUri)
            .Append(" | HTTP ").Append(options.HttpVersion)
            .Append(" | Concurrency ").Append(options.Concurrency)
            .Append(" | ConnectionClose ").Append(options.ConnectionClose)
            .Append(" | MaxRequest ").Append(options.MaxRequestTime)
            .Append(" | Ramp ").Append(options.RampPercentPerSecond.ToString("F1")).Append("%/s")
            .AppendLine();
        _buffer.Append("Elapsed: ").Append(snapshot.Elapsed.ToString(@"hh\:mm\:ss"))
            .Append(" / ").Append(options.Duration.ToString(@"hh\:mm\:ss"))
            .Append(" | Progress ").Append(progressBar)
            .AppendLine();
        _buffer.AppendLine(new string('─', Math.Max(40, Math.Min(width - 1, 180))));
        _buffer.Append("Req total=").Append(snapshot.TotalRequests)
            .Append(" success=").Append(snapshot.Successes)
            .Append(" errors=").Append(snapshot.Errors)
            .Append(" inflight=").Append(snapshot.Inflight)
            .Append(" opened_tcp=").Append(snapshot.OpenedConnections)
            .AppendLine();
        _buffer.Append("RPS avg=").Append(snapshot.Rps.ToString("F1"))
            .Append(" inst=").Append(instantRps.ToString("F1"))
            .Append(" peak=").Append(_peakInstantRps.ToString("F1"))
            .AppendLine();
        _buffer.Append("RPS current ").Append(currentRpsBar)
            .Append(" ").Append(instantRps.ToString("F1"))
            .Append(" req/s")
            .AppendLine();
        _buffer.Append("Latency avg=").Append(snapshot.AvgLatencyMs.ToString("F1"))
            .Append("ms p50=").Append(snapshot.P50Ms.ToString("F1"))
            .Append("ms p95=").Append(snapshot.P95Ms.ToString("F1"))
            .Append("ms p99=").Append(snapshot.P99Ms.ToString("F1"))
            .Append("ms")
            .AppendLine();
        _buffer.AppendLine();
        _buffer.Append("RPS graph ").Append(rpsGraph)
            .Append(" max=").Append(MaxValue(rpsData).ToString("F1"))
            .AppendLine();
        _buffer.Append("P95 graph ").Append(p95Graph)
            .Append(" max=").Append(MaxValue(p95Data).ToString("F1"))
            .Append("ms")
            .AppendLine();

        if (isFinal)
        {
            _buffer.AppendLine()
                .AppendLine(BuildFinalSummary(snapshot))
                .AppendLine("completed");
        }

        Console.Write(_buffer.ToString());
    }

    private static string BuildFinalSummary(MetricsSnapshot snapshot)
    {
        var total = snapshot.TotalRequests;
        var errorPercentage = total <= 0 ? 0d : (snapshot.Errors * 100d) / total;
        return $"summary success={snapshot.Successes} failed={snapshot.Errors} error_pct={errorPercentage:F2}% total={total}";
    }

    private static int GetTerminalWidth()
    {
        try
        {
            return Math.Clamp(Console.WindowWidth, 80, 240);
        }
        catch
        {
            return 120;
        }
    }

    private static string BuildProgressBar(TimeSpan elapsed, TimeSpan total, int width)
    {
        if (width <= 0)
        {
            return "[]";
        }

        var ratio = total <= TimeSpan.Zero ? 1d : Math.Clamp(elapsed.TotalSeconds / total.TotalSeconds, 0d, 1d);
        var filled = (int)Math.Round(width * ratio, MidpointRounding.AwayFromZero);
        if (filled > width)
        {
            filled = width;
        }

        return $"[{new string('#', filled)}{new string('-', width - filled)}]";
    }

    private static string BuildValueBar(double value, double maxValue, int width)
    {
        if (width <= 0)
        {
            return "[]";
        }

        var safeMax = maxValue <= 0 ? 1 : maxValue;
        var ratio = Math.Clamp(value / safeMax, 0d, 1d);
        var filled = (int)Math.Round(width * ratio, MidpointRounding.AwayFromZero);
        if (filled > width)
        {
            filled = width;
        }

        return $"[{new string('█', filled)}{new string(' ', width - filled)}]";
    }

    private static string BuildSparkline(double[] values, int width)
    {
        if (width <= 0)
        {
            return string.Empty;
        }

        if (values.Length == 0)
        {
            return new string('·', width);
        }

        var sampled = Resample(values, width);
        var maxValue = MaxValue(sampled);
        if (maxValue <= 0)
        {
            return new string('▁', width);
        }

        var chars = new char[sampled.Length];
        for (var index = 0; index < sampled.Length; index++)
        {
            var normalized = sampled[index] / maxValue;
            var blockIndex = (int)Math.Round(normalized * (SparklineBlocks.Length - 1));
            if (blockIndex < 0)
            {
                blockIndex = 0;
            }
            else if (blockIndex >= SparklineBlocks.Length)
            {
                blockIndex = SparklineBlocks.Length - 1;
            }

            chars[index] = SparklineBlocks[blockIndex];
        }

        return new string(chars);
    }

    private static double[] Resample(double[] source, int width)
    {
        if (source.Length <= width)
        {
            var padded = new double[width];
            var offset = width - source.Length;
            Array.Copy(source, 0, padded, offset, source.Length);
            return padded;
        }

        var sampled = new double[width];
        for (var bucket = 0; bucket < width; bucket++)
        {
            var start = bucket * source.Length / width;
            var end = (bucket + 1) * source.Length / width;
            if (end <= start)
            {
                end = start + 1;
            }

            double sum = 0;
            var count = 0;
            for (var index = start; index < end && index < source.Length; index++)
            {
                sum += source[index];
                count++;
            }

            sampled[bucket] = count == 0 ? 0 : sum / count;
        }

        return sampled;
    }

    private static double MaxValue(double[] values)
    {
        var maxValue = 0d;
        for (var index = 0; index < values.Length; index++)
        {
            if (values[index] > maxValue)
            {
                maxValue = values[index];
            }
        }

        return maxValue;
    }
}

internal sealed class RollingSeries
{
    private readonly double[] _values;
    private int _nextIndex;
    private int _count;

    public RollingSeries(int capacity)
    {
        _values = new double[Math.Max(1, capacity)];
    }

    public void Add(double value)
    {
        _values[_nextIndex] = value;
        _nextIndex++;
        if (_nextIndex == _values.Length)
        {
            _nextIndex = 0;
        }

        if (_count < _values.Length)
        {
            _count++;
        }
    }

    public double[] Snapshot()
    {
        var snapshot = new double[_count];
        if (_count == 0)
        {
            return snapshot;
        }

        if (_count < _values.Length)
        {
            Array.Copy(_values, snapshot, _count);
            return snapshot;
        }

        var tailLength = _values.Length - _nextIndex;
        Array.Copy(_values, _nextIndex, snapshot, 0, tailLength);
        if (_nextIndex > 0)
        {
            Array.Copy(_values, 0, snapshot, tailLength, _nextIndex);
        }

        return snapshot;
    }
}
