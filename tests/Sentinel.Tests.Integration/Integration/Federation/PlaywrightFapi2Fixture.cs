using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using DotNet.Testcontainers.Builders;
using Microsoft.Playwright;
using Testcontainers.Keycloak;

namespace Sentinel.Tests.Integration.Federation;

/// <summary>
///     xUnit async fixture for the FAPI 2.0 browser-mediated E2E tests: a real
///     Keycloak 26.6.4 container (the repo-pinned base image) importing the
///     sentinel-dast realm, and a headless Chromium instance via Microsoft.Playwright.
///
///     Configuration notes (all verified live):
///     - The DAST realm sets sslRequired: "all", so the container serves HTTPS
///       on 8443 with the repo-local CA/cert pair (same posture as the contract
///       gate); the browser trusts it via IgnoreHTTPSErrors, the fixture's
///       HttpClient pins the Sentinel CA.
///     - sentinel-dast.json already declares the FAPI 2.0 browser client
///       (sentinel-dast-victim: PAR-required, PKCE S256, DPoP-bound tokens,
///       redirect http://localhost:8081/callback) and the dast-victim-user, so
///       no admin-API provisioning is needed.
///     - The browser callback URI is intercepted with a route fulfillment
///       (204): Chromium would otherwise error on the unresolvable
///       localhost:8081 and Playwright's GotoAsync would throw; the
///       authorization code is captured from the intercepted request URL.
/// </summary>
public sealed class PlaywrightFapi2Fixture : IAsyncLifetime
{
    public const string RealmName = "sentinel-dast";
    public const string ClientId = "sentinel-dast-victim";
    public const string TestUsername = "dast-victim-user";
    public const string TestPassword = "DastTestPassword123!";
    public const string RedirectUri = "http://localhost:8081/callback";

    private static readonly Regex ErrorPagePattern =
        new("Invalid parameter|We are sorry|not included", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly KeycloakContainer _keycloak;
    private string _baseAddress = string.Empty;
    private IPlaywright? _playwright;
    private IBrowser? _browser;
    private CallbackServer? _callbackServer;

    public PlaywrightFapi2Fixture()
    {
        var repoRoot = GetRepoRoot();
        _keycloak = new KeycloakBuilder("quay.io/keycloak/keycloak:26.6.4")
            .WithUsername("admin")
            .WithPassword("admin")
            .WithEnvironment("KC_FEATURES", "dpop,par")
            // Mirrors the repo compose keycloak posture: HTTPS-only on 8443 with
            // the repo CA/cert pair. The DAST realm requires sslRequired "all",
            // so plain HTTP would be refused with 403.
            .WithEnvironment("KC_HEALTH_ENABLED", "true")
            .WithEnvironment("KC_HTTP_ENABLED", "false")
            .WithEnvironment("KC_HTTPS_PORT", "8443")
            .WithEnvironment("KC_HTTPS_CERTIFICATE_FILE", "/etc/x509/certs/keycloak.crt")
            .WithEnvironment("KC_HTTPS_CERTIFICATE_KEY_FILE", "/etc/x509/keys/keycloak.key")
            .WithPortBinding(8443, true)
            .WithWaitStrategy(Wait.ForUnixContainer()
                .UntilMessageIsLogged("Keycloak .* started in .*"))
            .WithRealm(Path.Combine(repoRoot, "infra", "keycloak", "realms", "sentinel-dast.json"))
            .WithResourceMapping(
                new FileInfo(Path.Combine(repoRoot, "infra", "certs", "keycloak.crt")),
                "/etc/x509/certs/",
                0, 0,
                DotNet.Testcontainers.Configurations.UnixFileModes.UserRead
                | DotNet.Testcontainers.Configurations.UnixFileModes.GroupRead
                | DotNet.Testcontainers.Configurations.UnixFileModes.OtherRead)
            .WithResourceMapping(
                new FileInfo(Path.Combine(repoRoot, "infra", "certs", "keycloak.key")),
                "/etc/x509/keys/",
                0, 0,
                DotNet.Testcontainers.Configurations.UnixFileModes.UserRead
                | DotNet.Testcontainers.Configurations.UnixFileModes.GroupRead
                | DotNet.Testcontainers.Configurations.UnixFileModes.OtherRead)
            .Build();
    }

    public string BaseAddress => _baseAddress;

    public Uri RealmUrl => new($"{_baseAddress}/realms/{RealmName}");

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability", "CA2000",
        Justification = "Handler is disposed via disposeHandler: true; client is disposed by the caller.")]
    public static HttpClient CreateTrustingHttpClient()
        => new(CreateSentinelCaTrustingHandler(), disposeHandler: true) { Timeout = TimeSpan.FromSeconds(30) };

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
            Args = ["--no-sandbox", "--disable-dev-shm-usage"]
        });

        // The DAST client's registered redirect_uri (http://localhost:8081/callback)
        // is served by a minimal local HTTP server so the browser callback
        // navigation succeeds and the code is readable from the final page URL.
        _callbackServer = new CallbackServer();
    }

    public async ValueTask DisposeAsync()
    {
        _callbackServer?.Dispose();

        if (_browser is not null)
        {
            await _browser.CloseAsync();
        }

        _playwright?.Dispose();
        await _keycloak.DisposeAsync();
    }

    /// <summary>
    ///     Executes the browser-mediated authorization: navigates to the
    ///     authorization URL, performs the Keycloak login, and returns either
    ///     the captured callback (code/state) or the error-page state Keycloak
    ///     renders for invalid requests.
    /// </summary>
    public async Task<BrowserFlowResult> ExecuteBrowserLoginAsync(Uri authorizationUrl)
    {
        var context = await _browser!.NewContextAsync(new BrowserNewContextOptions
        {
            IgnoreHTTPSErrors = true // self-signed Keycloak cert in the test container
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

            // PAR enforcement failures (reuse/expiry/direct-authorize) surface
            // as a Keycloak error PAGE (400), not a redirect - detect that first.
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

            // Wait for either the callback (code) or a Keycloak error page.
            var deadline = DateTime.UtcNow.AddSeconds(15);
            while (DateTime.UtcNow < deadline)
            {
                if (page.Url.Contains("localhost:8081", StringComparison.Ordinal))
                {
                    var query = ParseQuery(new Uri(page.Url).Query);
                    return new BrowserFlowResult(
                        query.GetValueOrDefault("code"),
                        query.GetValueOrDefault("state"),
                        query.GetValueOrDefault("error"),
                        null);
                }

                var bodyText = await ReadPageTextAsync(page);
                if (ErrorPagePattern.IsMatch(bodyText))
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
            if (ErrorPagePattern.IsMatch(bodyText))
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
        using var http = CreateTrustingHttpClient();
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
#pragma warning disable CA1031 // Container startup is retried on any transient failure; the retry loop is the handling strategy
            catch (Exception ex)
            {
                lastError = ex.Message;
            }
#pragma warning restore CA1031

            await Task.Delay(1000);
        }

        throw new TimeoutException($"Keycloak realm {RealmName} was not ready within 300 seconds: {lastError}");
    }

    /// <summary>Trusts only certificates signed by the repo-local Sentinel CA.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability", "CA2000",
        Justification = "The CA certificate must outlive the handler factory: the validation callback captures it and runs on every request.")]
    private static HttpClientHandler CreateSentinelCaTrustingHandler()
    {
        var ca = X509Certificate2.CreateFromPem(
            File.ReadAllText(Path.Combine(GetRepoRoot(), "infra", "certs", "ca.crt")));
        return new HttpClientHandler
        {
            AllowAutoRedirect = true,
            ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
                cert is not null && IsSignedBySentinelCa(new X509Certificate2(cert), ca)
        };
    }

    private static bool IsSignedBySentinelCa(X509Certificate2 cert, X509Certificate2 ca)
    {
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(ca);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            // Repo-issued certs carry a slightly forward NotBefore (clock drift at
            // generation time); pin within the validity window so the CA is the
            // asserted element.
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
        var directory = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Sentinel.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName
            ?? throw new DirectoryNotFoundException("Could not locate repository root (Sentinel.slnx).");
    }
}

public sealed record BrowserFlowResult(
    string? AuthorizationCode,
    string? State,
    string? Error,
    string? ErrorPageText);

/// <summary>
///     Minimal local HTTP server standing in for the OIDC client's redirect
///     endpoint. Playwright route interception does not catch 302-followed
///     navigations (verified empirically on 1.52.0: the redirect request is
///     sent to the network un-routed, producing ERR_CONNECTION_REFUSED), so
///     the redirect_uri http://localhost:8081/callback (registered in the DAST
///     realm) is served by a real listener: the browser navigation completes
///     and the authorization code is read from the final page URL.
/// </summary>
internal sealed class CallbackServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _acceptLoop;

    public CallbackServer()
    {
        _listener = new TcpListener(IPAddress.Loopback, 8081);
        _listener.Start();
        _acceptLoop = Task.Run(AcceptLoopAsync);
    }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                var client = await _listener.AcceptTcpClientAsync(_cts.Token);
                _ = Task.Run(() => HandleClientAsync(client, _cts.Token));
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException)
            {
                break;
            }
        }
    }

    private static async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        using (var stream = client.GetStream())
        {
            var buffer = new byte[8192];
            var total = 0;
            while (total < buffer.Length)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(total), ct);
                if (read == 0)
                {
                    break;
                }

                total += read;
                if (total >= 4 && buffer.AsSpan(total - 4, 4).SequenceEqual("\r\n\r\n"u8))
                {
                    break;
                }
            }

            // Any path (e.g. /callback, /favicon.ico) answers with an empty 200:
            // the browser completes the navigation and the test reads the code
            // from the resulting page URL.
            const string response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            await stream.WriteAsync(System.Text.Encoding.ASCII.GetBytes(response), ct);
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _cts.Dispose();
        try
        {
            _listener.Dispose();
        }
        catch (SocketException)
        {
            // listener already disposed
        }
    }
}

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class PlaywrightFapi2Collection : ICollectionFixture<PlaywrightFapi2Fixture>
{
    public const string Name = "Playwright FAPI 2";
}
