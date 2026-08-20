using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using DotNet.Testcontainers.Builders;
using Microsoft.Playwright;
using Testcontainers.Keycloak;
using Xunit;

namespace Sentinel.Tests.Integration.Federation;

/// <summary>
///     xUnit async fixture for the FAPI 2.0 browser-mediated E2E tests.
///     Spins up a real Keycloak 26.6.4 container with the sentinel-dast realm
///     and a headless Chromium instance via Microsoft.Playwright.
/// </summary>
public sealed partial class PlaywrightFapi2Fixture : IAsyncLifetime
{
    public const string RealmName = "sentinel-dast";
    public const string ClientId = "sentinel-dast-victim";
    public const string TestUsername = "dast-victim-user";
    public const string TestPassword = "DastTestPassword123!";

    private static readonly string RepoRoot = GetRepoRoot();

    // Native AOT compatible regex (replaces RegexOptions.Compiled)
    [GeneratedRegex("Invalid parameter|We are sorry|not included", RegexOptions.IgnoreCase)]
    private static partial Regex ErrorPagePattern();

    private readonly KeycloakContainer _keycloak;
    private readonly X509Certificate2 _sentinelCa;
    private readonly int _callbackPort;
    private readonly string _tempRealmPath;

    private string _baseAddress = string.Empty;
    private IPlaywright? _playwright;
    private IBrowser? _browser;
private CallbackServer? _callbackServer;

    /// <summary>Dynamic redirect URI matching the dynamically allocated callback port.</summary>
    public string RedirectUri => $"http://localhost:{_callbackPort}/callback";

    public PlaywrightFapi2Fixture()
    {
        _sentinelCa = X509Certificate2.CreateFromPem(
            File.ReadAllText(Path.Combine(RepoRoot, "infra", "certs", "ca.crt")));

        // 1. Dynamically assign port to prevent CI parallel execution collisions
        _callbackPort = GetFreeTcpPort();

        // 2. Patch the static realm JSON in-memory to use the dynamic port
        var originalRealmPath = Path.Combine(RepoRoot, "infra", "keycloak", "realms", "sentinel-dast.json");
        var realmJson = File.ReadAllText(originalRealmPath);
        realmJson = realmJson.Replace("http://localhost:8081/callback", $"http://localhost:{_callbackPort}/callback");

        // FIX: Must use a .json extension so Keycloak's DirImportProvider detects and imports it
        _tempRealmPath = Path.Combine(Path.GetTempPath(), $"sentinel-dast-{Guid.NewGuid():N}.json");
        File.WriteAllText(_tempRealmPath, realmJson);

        _keycloak = new KeycloakBuilder("quay.io/keycloak/keycloak:26.6.4")
            .WithUsername("admin")
            .WithPassword("admin")
            .WithEnvironment("KC_FEATURES", "dpop,par")
            .WithEnvironment("KC_HEALTH_ENABLED", "true")
            .WithEnvironment("KC_HTTP_ENABLED", "false")
            .WithEnvironment("KC_HTTPS_PORT", "8443")
            .WithEnvironment("KC_HTTPS_CERTIFICATE_FILE", "/etc/x509/certs/keycloak.crt")
            .WithEnvironment("KC_HTTPS_CERTIFICATE_KEY_FILE", "/etc/x509/keys/keycloak.key")
            .WithPortBinding(8443, true)
            .WithWaitStrategy(Wait.ForUnixContainer()
                .UntilMessageIsLogged(".*Keycloak .* started in .*"))
            .WithRealm(_tempRealmPath)
            .WithResourceMapping(
                new FileInfo(Path.Combine(RepoRoot, "infra", "certs", "keycloak.crt")),
                "/etc/x509/certs/",
                0, 0,
                DotNet.Testcontainers.Configurations.UnixFileModes.UserRead
                | DotNet.Testcontainers.Configurations.UnixFileModes.GroupRead
                | DotNet.Testcontainers.Configurations.UnixFileModes.OtherRead)
            .WithResourceMapping(
                new FileInfo(Path.Combine(RepoRoot, "infra", "certs", "keycloak.key")),
                "/etc/x509/keys/",
                0, 0,
                DotNet.Testcontainers.Configurations.UnixFileModes.UserRead
                | DotNet.Testcontainers.Configurations.UnixFileModes.GroupRead
                | DotNet.Testcontainers.Configurations.UnixFileModes.OtherRead)
            .Build();
    }

    public string BaseAddress => _baseAddress;
    public Uri RealmUrl => new($"{_baseAddress}/realms/{RealmName}");
    public int CallbackPort => _callbackPort;

public static HttpClient CreateTrustingHttpClient(X509Certificate2 ca)
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
                cert is not null && IsSignedBySentinelCa(new X509Certificate2(cert), ca)
        };
        return new HttpClient(handler, disposeHandler: true) { Timeout = TimeSpan.FromSeconds(30) };
    }

    public HttpClient CreateTrustingHttpClient()
        => CreateTrustingHttpClient(_sentinelCa);

    public async ValueTask InitializeAsync()
    {
        await _keycloak.StartAsync();
        _baseAddress = new UriBuilder(
            Uri.UriSchemeHttps,
            _keycloak.Hostname,
            _keycloak.GetMappedPublicPort(8443)).ToString().TrimEnd('/');

        await WaitForRealmReadyAsync();

        _playwright = await Microsoft.Playwright.Playwright.CreateAsync();
        _browser = await _playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
        {
            Headless = true,
            Args = ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
        });

        _callbackServer = new CallbackServer(_callbackPort);
    }

    public async ValueTask DisposeAsync()
    {
        _callbackServer?.Dispose();

        if (_browser is not null)
        {
            await _browser.CloseAsync();
            _browser = null;
        }

        _playwright?.Dispose();
        _playwright = null;

        await _keycloak.DisposeAsync();
        _sentinelCa.Dispose(); // Prevent crypto handle leaks

        if (File.Exists(_tempRealmPath))
        {
            try { File.Delete(_tempRealmPath); } catch { /* best effort cleanup */ }
        }
    }

    public async Task<BrowserFlowResult> ExecuteBrowserLoginAsync(Uri authorizationUrl)
    {
        var context = await _browser!.NewContextAsync(new BrowserNewContextOptions
        {
            IgnoreHTTPSErrors = true
        });

        var failedRequests = new List<string>();
        var consoleMessages = new List<string>();

        try
        {
            var page = await context.NewPageAsync();
            page.RequestFailed += (_, request) => failedRequests.Add($"{request.Url} -> {request.Failure}");
            page.Console += (_, message) => consoleMessages.Add(message.Text);

            await page.GotoAsync(authorizationUrl.ToString(), new PageGotoOptions
            {
                WaitUntil = WaitUntilState.DOMContentLoaded,
                Timeout = 30000
            });

            var errorText = await WaitForErrorPageAsync(page);
            if (errorText is not null)
            {
                return new BrowserFlowResult(null, null, null, errorText);
            }

            if (!page.Url.Contains("/login-actions/", StringComparison.Ordinal))
            {
                return new BrowserFlowResult(null, null, "unexpected page", await ReadPageTextAsync(page));
            }

            await page.WaitForSelectorAsync("#username", new PageWaitForSelectorOptions { Timeout = 10000 });
            await page.FillAsync("#username", TestUsername);
            await page.FillAsync("#password", TestPassword);
            await page.ClickAsync("#kc-login");

            var deadline = DateTime.UtcNow.AddSeconds(15);
            while (DateTime.UtcNow < deadline)
            {
                // Use the dynamically assigned port
                if (page.Url.Contains($"localhost:{_callbackPort}", StringComparison.Ordinal))
                {
                    var query = ParseQuery(new Uri(page.Url).Query);
                    return new BrowserFlowResult(
                        query.GetValueOrDefault("code"),
                        query.GetValueOrDefault("state"),
                        query.GetValueOrDefault("error"),
                        null);
                }

                var bodyText = await ReadPageTextAsync(page);
                if (ErrorPagePattern().IsMatch(bodyText))
                {
                    return new BrowserFlowResult(null, null, null, bodyText);
                }

                await Task.Delay(250);
            }

            return new BrowserFlowResult(
                null,
                null,
                $"timeout waiting for login completion; page.Url={page.Url}; failedRequests=[{string.Join(" | ", failedRequests)}]; console=[{string.Join(" | ", consoleMessages)}]",
                await ReadPageTextAsync(page));
        }
        finally
        {
            await context.CloseAsync();
        }
    }

    private static async Task<string?> WaitForErrorPageAsync(IPage page)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            var bodyText = await ReadPageTextAsync(page);
            if (ErrorPagePattern().IsMatch(bodyText))
            {
                return bodyText;
            }

            await Task.Delay(200);
        }

        return null;
    }

    private static async Task<string> ReadPageTextAsync(IPage page)
    {
        try
        {
            return await page.TextContentAsync("body") ?? string.Empty;
        }
        catch (PlaywrightException)
        {
            return string.Empty;
        }
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var part in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = part.IndexOf('=');
            if (separator > 0)
            {
                result[Uri.UnescapeDataString(part[..separator])] =
                    Uri.UnescapeDataString(part[(separator + 1)..]);
            }
        }

        return result;
    }

    private async Task WaitForRealmReadyAsync()
    {
        using var http = CreateTrustingHttpClient(_sentinelCa);
        var deadline = DateTime.UtcNow.AddSeconds(300);
        var lastError = string.Empty;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                var response = await http.GetAsync($"{RealmUrl}/.well-known/openid-configuration", CancellationToken.None);
                if (response.IsSuccessStatusCode)
                {
                    return;
                }

                lastError = $"discovery returned {response.StatusCode}";
            }
            catch (Exception ex)
            {
                lastError = ex.Message;
            }

            await Task.Delay(1000);
        }

        throw new TimeoutException($"Keycloak realm {RealmName} was not ready within 300 seconds: {lastError}");
    }

    private static bool IsSignedBySentinelCa(X509Certificate2 cert, X509Certificate2 ca)
    {
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(ca);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            // Repo-issued certs carry a slightly forward NotBefore (clock drift at generation time)
            chain.ChainPolicy.VerificationTime = cert.NotBefore.AddHours(1);
            return chain.Build(cert);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static string GetRepoRoot()
    {
        // AppContext.BaseDirectory is preferred over AppDomain in modern .NET
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Sentinel.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName
            ?? throw new DirectoryNotFoundException("Could not locate repository root (Sentinel.slnx).");
    }

    private static int GetFreeTcpPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}

public sealed record BrowserFlowResult(
    string? AuthorizationCode,
    string? State,
    string? Error,
    string? ErrorPageText);

/// <summary>
///     Minimal local HTTP server standing in for the OIDC client's redirect endpoint.
/// </summary>
internal sealed class CallbackServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _acceptLoop;

    public CallbackServer(int port)
    {
        _listener = new TcpListener(IPAddress.Loopback, port);
        _listener.Start();
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_cts.Token));
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var client = await _listener.AcceptTcpClientAsync(ct);
                _ = Task.Run(() => HandleClientAsync(client, ct), ct);
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException) { break; }
        }
    }

    private static async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        await using (var stream = client.GetStream())
        {
            var buffer = new byte[4096];
            var total = 0;
            while (total < buffer.Length)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(total), ct);
                if (read == 0) break;
                total += read;
                if (total >= 4 && buffer.AsSpan(total - 4, 4).SequenceEqual("\r\n\r\n"u8)) break;
            }

            const string response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(response), ct);
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _cts.Dispose();
        try { _listener.Stop(); _listener.Dispose(); } catch { /* listener already disposed */ }
    }
}

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class PlaywrightFapi2Collection : ICollectionFixture<PlaywrightFapi2Fixture>
{
    public const string Name = "Playwright FAPI 2";
}
