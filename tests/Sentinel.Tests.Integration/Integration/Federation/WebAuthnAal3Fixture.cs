using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;
using DotNet.Testcontainers.Networks;
using FluentAssertions;
using Microsoft.Playwright;
using Testcontainers.Keycloak;
using Xunit;

namespace Sentinel.Tests.Integration.Federation;

/// <summary>
///     xUnit async fixture for ADR-2026-006 (WebAuthn AAL3): a hermetic
///     proof-of-enforcement suite against a real Keycloak 26.6.4 container.
///     Implements split-validation: CDP virtual authenticator for ceremony flow,
///     separate realm variant for MDS3 attestation enforcement.
/// </summary>
public sealed class WebAuthnAal3Fixture : IAsyncLifetime
{
    public const string RealmName = "sentinel-dast";
    public const string Mds3RealmName = "sentinel-dast-mds3";
    public const string Aal3ClientId = "sentinel-dast-aal3";
    public const string Aal3BrowserFlow = "government-aal3-browser";

    public const string EnrollUsername = "aal3-enroll-user";
    public const string AssertUsername = "aal3-assert-user";
    public const string TotpUsername = "aal3-totp-user";
    public const string LockoutUsername = "aal3-lockout-user";
    public const string RogueUsername = "aal3-rogue-user";
    public const string TestPassword = "Aal3TestPassword123!";

    private const string Mds3Hostname = "mds3.fidoalliance.org";
    private const string TruststorePassword = "sentinel-mds3-mock";
    public const string BruteForceUsername = "aal3-bruteforce-user";

    // ✅ FIX: Lazy singleton handler prevents socket exhaustion under parallel execution
    private static readonly Lazy<HttpClientHandler> SentinelCaHandler = new(CreateSentinelCaTrustingHandler);

    private readonly INetwork _network;
    private readonly IContainer _mds3Mock;
    private readonly KeycloakContainer _keycloak;
    private readonly string _artifactsDir;
    private readonly string _accessLogDir;
    private readonly int _callbackPort;
    private IPlaywright? _playwright;
    private IBrowser? _browser;
    private CallbackServer? _callbackServer;
    private string _baseAddress = string.Empty;

    // ✅ FIX: Centralized admin client with thread-safe token lifecycle
    private HttpClient? _adminHttpClient;
    private string? _adminToken;
    private DateTimeOffset _adminTokenExpiresAt = DateTimeOffset.MinValue;
    private readonly SemaphoreSlim _adminLock = new(1, 1);

    public string BaseAddress => _baseAddress;
    public Uri RealmUrl => new($"{_baseAddress}/realms/{RealmName}");
    public Uri AdminUrl => new($"{_baseAddress}/admin/realms/{RealmName}");
    public string Mds3ArtifactsDir => _artifactsDir;
    public int Mds3PublicPort => _mds3Mock.GetMappedPublicPort(443);
    public int CallbackPort => _callbackPort;
    public string TotpSecret { get; private set; } = string.Empty;

    /// <summary>Dynamic redirect URI matching the dynamically allocated callback port.</summary>
    public string RedirectUri => $"http://localhost:{_callbackPort}/callback";

    public WebAuthnAal3Fixture()
    {
        var repoRoot = GetRepoRoot();
        _artifactsDir = Path.Combine(Path.GetTempPath(), $"sentinel-mds3-{Guid.NewGuid():N}");
        _accessLogDir = Path.Combine(_artifactsDir, "log");
        Directory.CreateDirectory(_accessLogDir);

        GenerateMds3Artifacts(_artifactsDir, _accessLogDir);
        CreateRealmVariants(_artifactsDir);

        // ✅ FIX: Dynamic port allocation prevents CI parallel execution collisions
        _callbackPort = GetFreeTcpPort();

        _network = new NetworkBuilder()
            .WithName($"sentinel-aal3-network-{Guid.NewGuid():N}")
            .Build();

        _mds3Mock = new ContainerBuilder("nginx:1.27-alpine")
            .WithNetwork(_network)
            .WithNetworkAliases(Mds3Hostname)
            .WithPortBinding(443, true)
            .WithBindMount(Path.Combine(_artifactsDir, "nginx.conf"), "/etc/nginx/conf.d/default.conf")
            .WithBindMount(Path.Combine(_artifactsDir, "tls.crt"), "/etc/nginx/tls/tls.crt")
            .WithBindMount(Path.Combine(_artifactsDir, "tls.key"), "/etc/nginx/tls/tls.key")
            .WithBindMount(Path.Combine(_artifactsDir, "blob.jwt"), "/usr/share/nginx/html/index.html")
            .WithBindMount(_accessLogDir, "/var/log/nginx")
            .WithWaitStrategy(Wait.ForUnixContainer().UntilInternalTcpPortIsAvailable(443))
            .Build();

        _keycloak = new KeycloakBuilder("quay.io/keycloak/keycloak:26.6.4")
            .WithUsername("admin")
            .WithPassword("admin")
            .WithNetwork(_network)
            .WithEnvironment("KC_FEATURES", "dpop,par")
            .WithEnvironment("KC_HEALTH_ENABLED", "true")
            .WithEnvironment("KC_HTTP_ENABLED", "false")
            .WithEnvironment("KC_HTTPS_PORT", "8443")
            .WithEnvironment("KC_HTTPS_CERTIFICATE_FILE", "/etc/x509/certs/keycloak.crt")
            .WithEnvironment("KC_HTTPS_CERTIFICATE_KEY_FILE", "/etc/x509/keys/keycloak.key")
            .WithEnvironment("KC_TRUSTSTORE_FILE", "/opt/keycloak/mds3/mds3-truststore.p12")
            .WithEnvironment("KC_TRUSTSTORE_PASSWORD", TruststorePassword)
            .WithPortBinding(8443, true)
            .WithWaitStrategy(Wait.ForUnixContainer()
                .UntilMessageIsLogged("Keycloak .* started in .*"))
            .WithRealm(Path.Combine(_artifactsDir, "sentinel-dast-aal3.json"))
            .WithResourceMapping(
                new FileInfo(Path.Combine(_artifactsDir, "sentinel-dast-mds3.json")),
                "/opt/keycloak/data/import/",
                0, 0,
                DotNet.Testcontainers.Configurations.UnixFileModes.UserRead
                | DotNet.Testcontainers.Configurations.UnixFileModes.GroupRead
                | DotNet.Testcontainers.Configurations.UnixFileModes.OtherRead)
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
            .WithResourceMapping(
                new FileInfo(Path.Combine(_artifactsDir, "mds3-truststore.p12")),
                "/opt/keycloak/mds3/",
                0, 0,
                DotNet.Testcontainers.Configurations.UnixFileModes.UserRead
                | DotNet.Testcontainers.Configurations.UnixFileModes.GroupRead
                | DotNet.Testcontainers.Configurations.UnixFileModes.OtherRead)
            .Build();
    }

    // =========================================================================
    // Admin Client Lifecycle (Thread-Safe Token Refresh)
    // =========================================================================
    public const string FixedTotpSecret = "JBSWY3DPEHPK3PXP"; // RFC 4648 Base32 test vector

    public async Task<string> CreateTotpUserAsync(
        string username,
        string password,
        string base32Secret = FixedTotpSecret,
        string realm = RealmName,
        CancellationToken ct = default)
    {
        var payload = new JsonObject
        {
            ["username"] = username,
            ["enabled"] = true,
            ["email"] = $"{username}@sentinel.test",
            ["emailVerified"] = true,
            ["realmRoles"] = new JsonArray("user"),
            ["credentials"] = new JsonArray(
                new JsonObject
                {
                    ["type"] = "password",
                    ["value"] = password,
                    ["temporary"] = false
                },
                new JsonObject
                {
                    ["type"] = "otp",
                    ["userLabel"] = "aal3-test-totp",
                    ["secretData"] = JsonSerializer.Serialize(new { value = base32Secret }),
                    ["credentialData"] = JsonSerializer.Serialize(new { subType = "totp", digits = 6, counter = 0, period = 30, algorithm = "HmacSHA1" }),
                    ["temporary"] = false
                }
            ),
            ["requiredActions"] = new JsonArray()
        };

        var http = await GetAdminClientAsync(ct);
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{_baseAddress}/admin/realms/{realm}/users")
        {
            Content = new StringContent(payload.ToJsonString(), Encoding.UTF8, "application/json")
        };

        using var response = await http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();

        var location = response.Headers.Location?.ToString()
                       ?? throw new InvalidOperationException("User creation returned no Location header");
        return location[(location.LastIndexOf('/') + 1)..];
    }
    public async Task<HttpClient> GetAdminClientAsync(CancellationToken ct = default)
    {
        await _adminLock.WaitAsync(ct);
        try
        {
            if (_adminHttpClient is null || DateTimeOffset.UtcNow >= _adminTokenExpiresAt)
            {
                _adminHttpClient?.Dispose();

                using var tokenRequest = new HttpRequestMessage(HttpMethod.Post,
                    $"{_baseAddress}/realms/master/protocol/openid-connect/token")
                {
                    Content = new FormUrlEncodedContent(new Dictionary<string, string>
                    {
                        ["client_id"] = "admin-cli",
                        ["grant_type"] = "password",
                        ["username"] = "admin",
                        ["password"] = "admin"
                    })
                };

                using var tokenClient = CreateTrustingHttpClient();
                using var response = await tokenClient.SendAsync(tokenRequest, ct);
                response.EnsureSuccessStatusCode();

                using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
                _adminToken = doc.RootElement.GetProperty("access_token").GetString()
                    ?? throw new InvalidOperationException("Admin token response missing access_token");

                var expiresIn = doc.RootElement.GetProperty("expires_in").GetInt32();
                _adminTokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(Math.Max(expiresIn - 30, 10));

                _adminHttpClient = CreateTrustingHttpClient();
                _adminHttpClient.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", _adminToken);
            }

            return _adminHttpClient;
        }
        finally
        {
            _adminLock.Release();
        }
    }

    public async Task<string> GetUserIdAsync(string username, CancellationToken ct = default)
    {
        var http = await GetAdminClientAsync(ct);
        using var response = await http.GetAsync(
            $"{AdminUrl}/users?username={Uri.EscapeDataString(username)}&exact=true", ct);
        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        return doc.RootElement.EnumerateArray().Single().GetProperty("id").GetString()
            ?? throw new InvalidOperationException($"User {username} not found");
    }

    public async Task<string> CreateUserAsync(
        string username,
        string password,
        IReadOnlyList<string>? requiredActions = null,
        string realm = RealmName,
        CancellationToken ct = default)
    {
        var payload = new JsonObject
        {
            ["username"] = username,
            ["enabled"] = true,
            ["email"] = $"{username}@sentinel.test",
            ["emailVerified"] = true,
            ["realmRoles"] = new JsonArray("user"),
            ["credentials"] = new JsonArray(new JsonObject
            {
                ["type"] = "password",
                ["value"] = password,
                ["temporary"] = false
            }),
            ["requiredActions"] = new JsonArray(
                requiredActions?.Select(a => (JsonNode)a).ToArray() ?? [])
        };

        var http = await GetAdminClientAsync(ct);
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{_baseAddress}/admin/realms/{realm}/users")
        {
            Content = new StringContent(payload.ToJsonString(), Encoding.UTF8, "application/json")
        };

        using var response = await http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();

        var location = response.Headers.Location?.ToString()
            ?? throw new InvalidOperationException("User creation returned no Location header");
        return location[(location.LastIndexOf('/') + 1)..];
    }

    public async Task RemoveWebAuthnCredentialsAsync(string userId, CancellationToken ct = default)
    {
        var http = await GetAdminClientAsync(ct);
        using var get = await http.GetAsync($"{AdminUrl}/users/{userId}/credentials", ct);
        get.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await get.Content.ReadAsStringAsync(ct));
        foreach (var credential in doc.RootElement.EnumerateArray())
        {
            var type = credential.GetProperty("type").GetString();
            if (type is "webauthn" or "webauthn-passwordless")
            {
                var credentialId = credential.GetProperty("id").GetString()!;
                using var delete = await http.DeleteAsync(
                    $"{AdminUrl}/users/{userId}/credentials/{credentialId}", ct);
                delete.EnsureSuccessStatusCode();
            }
        }
    }

    public async Task<Dictionary<string, string>> GetRealmAttributesAsync(CancellationToken ct = default)
    {
        var node = JsonNode.Parse(
            await File.ReadAllTextAsync(Path.Combine(_artifactsDir, "sentinel-dast-aal3.json"), ct))!;
        var result = new Dictionary<string, string>(StringComparer.Ordinal);

        if (node["attributes"] is JsonObject attrs)
        {
            foreach (var (key, value) in attrs)
                result[key] = value?.GetValue<string>() ?? string.Empty;
        }

        if (node["browserFlow"]?.GetValue<string>() is { Length: > 0 } browserFlow)
            result["browserFlow"] = browserFlow;

        return result;
    }

    // =========================================================================
    // FAPI Client Factory
    // =========================================================================

    public Fapi2BrowserClient CreateFapiClient(string realm = RealmName, string clientId = Aal3ClientId)
        => new(CreateTrustingHttpClient(), clientId, RedirectUri, BaseAddress, realm);

    // =========================================================================
    // Ceremony Session Management
    // =========================================================================

    public async Task<CeremonySession> StartCeremonyAsync(
        string realm = RealmName,
        string clientId = Aal3ClientId,
        CancellationToken ct = default)
    {
        var client = CreateFapiClient(realm, clientId);
        var (verifier, challenge) = Fapi2BrowserClient.GeneratePkceS256();
        var state = Fapi2BrowserClient.GenerateState();
        var nonce = Fapi2BrowserClient.GenerateNonce();
        var par = await client.SubmitParRequestAsync("openid profile email", challenge, state, nonce, ct: ct);
        var authorizationUrl = client.BuildAuthorizationUrl(par.RequestUri);

        var context = await _browser!.NewContextAsync(new BrowserNewContextOptions
        {
            IgnoreHTTPSErrors = true
        });

        var page = await context.NewPageAsync();

        // Attach diagnostics for browser console and errors
        page.Console += (_, msg) => Console.WriteLine($"[Browser Console] {msg.Type}: {msg.Text}");
        page.PageError += (_, err) => Console.WriteLine($"[Browser PageError] {err}");

        var cdp = await context.NewCDPSessionAsync(page);
        await cdp.SendAsync("WebAuthn.enable");
        await cdp.SendAsync("WebAuthn.addVirtualAuthenticator", new Dictionary<string, object>
        {
            ["options"] = new Dictionary<string, object>
            {
                ["protocol"] = "ctap2",
                ["transport"] = "usb",
                ["hasResidentKey"] = true,
                ["hasUserVerification"] = true,
                ["isUserVerified"] = true,
                ["automaticPresenceSimulation"] = true
            }
        });

        await page.GotoAsync(authorizationUrl.ToString(), new PageGotoOptions
        {
            WaitUntil = WaitUntilState.DOMContentLoaded,
            Timeout = 30000
        });

        return new CeremonySession(context, page, cdp, client, verifier);
    }

    // =========================================================================
    // Static Ceremony Helpers
    // =========================================================================

    public static async Task CompleteLoginAsync(CeremonySession session, string username, string password)
    {
        await session.Page.WaitForSelectorAsync("#username", new PageWaitForSelectorOptions { Timeout = 20000 });
        await session.Page.FillAsync("#username", username);

        // Check if password field is on the same page or if it's a 2-step login
        var passwordInput = await session.Page.QuerySelectorAsync("#password");
        if (passwordInput is not null && await passwordInput.IsVisibleAsync())
        {
            await passwordInput.FillAsync(password);
            await session.Page.ClickAsync("#kc-login, input[type='submit'], button[type='submit']");
        }
        else
        {
            // 2-step login: submit username first, then wait for password field
            await session.Page.ClickAsync("#kc-login, input[type='submit'], button[type='submit']");
            var pwField = await session.Page.WaitForSelectorAsync("#password", new PageWaitForSelectorOptions { Timeout = 10000 });
            if (pwField is not null)
            {
                await pwField.FillAsync(password);
                await session.Page.ClickAsync("#kc-login, input[type='submit'], button[type='submit']");
            }
        }

        await Task.Delay(1000);
    }

    public static async Task WaitForOtpFormAsync(CeremonySession session)
    {
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (DateTime.UtcNow < deadline)
        {
            // 1. Check if OTP input is visible
            var otpInput = await session.Page.QuerySelectorAsync("#otp, input[name='otp'], #totp, input[name='totp']");
            if (otpInput is not null && await otpInput.IsVisibleAsync())
            {
                return;
            }

            // 2. Click "Try another way" / "Other ways to authenticate" if on WebAuthn screen
            var tryAnotherWay = await session.Page.QuerySelectorAsync(
                "#try-another-way, #kc-try-another-way, a:has-text('Try another way'), a:has-text('Other ways'), a:has-text('recovery')");
            if (tryAnotherWay is not null && await tryAnotherWay.IsVisibleAsync())
            {
                await tryAnotherWay.ClickAsync();
                await Task.Delay(500);

                var otpOption = await session.Page.QuerySelectorAsync(
                    ".select-authenticator-otp, a:has-text('Authenticator Application'), a:has-text('OTP'), [data-provider-id='auth-otp-form']");
                if (otpOption is not null && await otpOption.IsVisibleAsync())
                {
                    await otpOption.ClickAsync();
                    await Task.Delay(500);
                }
                continue;
            }

            await Task.Delay(250);
        }

        var url = session.Page.Url;
        var body = await session.Page.TextContentAsync("body") ?? string.Empty;
        throw new TimeoutException($"Timed out waiting for OTP form. Current URL: {url}. Body: {body[..Math.Min(500, body.Length)]}");
    }
    public static async Task SubmitOtpAsync(CeremonySession session, string code)
    {
        var otpInput = await session.Page.WaitForSelectorAsync(
            "#otp, input[name='otp'], #totp, input[name='totp']",
            new PageWaitForSelectorOptions { Timeout = 10000 });

        if (otpInput is not null)
        {
            await otpInput.FillAsync(code);

            var loginBtn = await session.Page.QuerySelectorAsync(
                "#kc-login, input[name='login'], input[type='submit'], button[type='submit']");
            if (loginBtn is not null && await loginBtn.IsVisibleAsync())
            {
                await loginBtn.ClickAsync();
            }
            else
            {
                await otpInput.PressAsync("Enter");
            }
        }

        await Task.Delay(1500);
    }


    public static async Task WaitForTotpSetupAsync(CeremonySession session)
    {
        var deadline = DateTime.UtcNow.AddSeconds(45);
        while (DateTime.UtcNow < deadline)
        {
            var stage = await FindInteractiveStageAsync(session.Page);
            switch (stage)
            {
                case "register":
                    var regBtn = await session.Page.QuerySelectorAsync("#registerWebAuthn, input[name='registerWebAuthn']");
                    if (regBtn is not null && await regBtn.IsVisibleAsync())
                    {
                        await regBtn.ClickAsync();
                        await Task.Delay(2500);
                    }
                    continue;

                case "save_webauthn":
                    var saveBtn = await session.Page.QuerySelectorAsync("#saveWebAuthn, #kc-save, button[type='submit'], input[type='submit'], .btn-primary");
                    if (saveBtn is not null && await saveBtn.IsVisibleAsync())
                    {
                        await saveBtn.ClickAsync();
                        await Task.Delay(1500);
                    }
                    continue;

                case "authenticate":
                    var authBtn = await session.Page.QuerySelectorAsync("#authenticateWebAuthnButton, input[name='authenticateWebAuthnButton']");
                    if (authBtn is not null && await authBtn.IsVisibleAsync())
                    {
                        await authBtn.ClickAsync();
                        await Task.Delay(2000);
                    }
                    continue;

                case "totp":
                    return;

                case "login":
                    throw new InvalidOperationException(
                        $"Unexpected login page during TOTP setup; url={session.Page.Url}");
            }

            await Task.Delay(250);
        }

        throw new TimeoutException($"TOTP setup page not reached; url={session.Page.Url}");
    }

    /// <summary>
    /// Extracts TOTP secret from the CONFIGURE_TOTP page using multiple strategies.
    /// Keycloak 26.x keycloak.v2 theme renders the secret as text below the QR code,
    /// often in a code element, with data-totp-secret attribute, or as plain text.
    /// </summary>
    public static async Task<string> ReadTotpSecretAsync(CeremonySession session)
    {
        const string jsExtract = """
        (() => {
            // 1. Keycloak ALWAYS embeds the exact raw Base32 secret in this hidden input:
            const hiddenSecret = document.querySelector('input#totpSecret, input[name="totpSecret"]');
            if (hiddenSecret?.value?.trim()) return hiddenSecret.value.trim();

            // 2. Specific secret text element:
            const keyEl = document.querySelector('#kc-totp-secret-key, [data-totp-secret]');
            if (keyEl?.textContent?.trim()) return keyEl.textContent.trim();
            if (keyEl?.getAttribute('data-totp-secret')?.trim()) return keyEl.getAttribute('data-totp-secret').trim();

            // 3. QR code URI (otpauth://totp/...secret=BASE32):
            const qrImg = document.querySelector('img#kc-totp-secret-qr-code, img[alt*="totp"], img[src*="otpauth"]');
            const qrSrc = qrImg?.src || qrImg?.getAttribute('alt') || '';
            const match = qrSrc.match(/secret=([A-Z2-7]+)/i);
            if (match) return match[1];

            // 4. Text pattern fallback:
            const bodyText = document.body.innerText || '';
            const textMatch = bodyText.match(/(?:[A-Z2-7]{4}[-\s]?){4,8}/i);
            if (textMatch) return textMatch[0];

            return null;
        })()
        """;

        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (DateTime.UtcNow < deadline)
        {
            var secret = await session.Page.EvaluateAsync<string>(jsExtract);
            if (!string.IsNullOrWhiteSpace(secret))
            {
                var cleanSecret = new string(secret.Where(c => !char.IsWhiteSpace(c) && c != '-' && c != '=').ToArray());
                if (cleanSecret.Length >= 16)
                {
                    return cleanSecret;
                }
            }
            await Task.Delay(250);
        }

        throw new InvalidOperationException($"Could not extract TOTP secret from setup page: {session.Page.Url}");
    }

    public static async Task SubmitTotpSetupAsync(CeremonySession session, string base32Secret)
    {
        var cleanSecret = new string(base32Secret.Where(c => !char.IsWhiteSpace(c) && c != '-' && c != '=').ToArray());
        var code = ComputeTotp(cleanSecret);

        var userLabel = await session.Page.QuerySelectorAsync("#userLabel, input[name='userLabel']");
        if (userLabel is not null && await userLabel.IsVisibleAsync())
        {
            await userLabel.FillAsync("aal3-test-totp");
        }

        var totpInput = await session.Page.QuerySelectorAsync("#totp, input[name='totp']");
        if (totpInput is not null)
        {
            await totpInput.FillAsync(code);
            // Pressing Enter in the input field triggers the form submit event reliably
            await totpInput.PressAsync("Enter");
        }

        // Also click the primary submit button if form submission is still pending
        var saveBtn = await session.Page.QuerySelectorAsync(
            "#saveTOTPBtn, #kc-login, #kc-save, button[type='submit']:not(#cancelTOTPBtn):not([name*='cancel']), input[type='submit']:not(#cancelTOTPBtn):not([name*='cancel'])");
        if (saveBtn is not null && await saveBtn.IsVisibleAsync())
        {
            await saveBtn.ClickAsync();
        }

        // Wait up to 10 seconds for Keycloak to validate TOTP and redirect away from CONFIGURE_TOTP
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (DateTime.UtcNow < deadline)
        {
            if (!session.Page.Url.Contains("execution=CONFIGURE_TOTP", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            // Fast-fail if Keycloak displays an error
            var errorBanner = await session.Page.QuerySelectorAsync(
                ".alert-error, .alert-danger, .pf-m-danger, #input-error, .pf-v5-c-form__helper-text");
            if (errorBanner is not null)
            {
                var errorText = await errorBanner.TextContentAsync();
                if (!string.IsNullOrWhiteSpace(errorText) && !errorText.Contains("success", StringComparison.OrdinalIgnoreCase))
                {
                    var bodyText = await session.Page.TextContentAsync("body") ?? string.Empty;
                    throw new InvalidOperationException(
                        $"Keycloak rejected TOTP setup. Error: '{errorText.Trim()}'. Code: {code}, Secret: {cleanSecret}. Page: {bodyText[..Math.Min(300, bodyText.Length)]}");
                }
            }

            await Task.Delay(250);
        }
    }

    public static async Task<string> WaitForAuthorizationCodeAsync(CeremonySession session)
    {
        var deadline = DateTime.UtcNow.AddSeconds(45);

        while (DateTime.UtcNow < deadline)
        {
            var url = session.Page.Url;

            // 1. Check for callback URL with authorization code
            if (url.Contains("/callback", StringComparison.OrdinalIgnoreCase) ||
                url.Contains($"localhost:{session.CallbackPort}", StringComparison.Ordinal))
            {
                var query = ParseQuery(new Uri(url).Query);
                if (query.TryGetValue("code", out var code) && !string.IsNullOrEmpty(code))
                {
                    return code;
                }
            }

            // 2. Handle passkey label prompt: ONLY click save if the label input is visible!
            var userLabelInput = await session.Page.QuerySelectorAsync(
                "#userLabel, input[name='userLabel'], #authenticatorLabel, input[name='authenticatorLabel']");
            if (userLabelInput is not null && await userLabelInput.IsVisibleAsync())
            {
                await userLabelInput.FillAsync("sentinel-passkey");
                var saveBtn = await session.Page.QuerySelectorAsync(
                    "#saveWebAuthn, #kc-save, button[type='submit'], input[type='submit']");
                if (saveBtn is not null && await saveBtn.IsVisibleAsync())
                {
                    await saveBtn.ClickAsync();
                    await Task.Delay(1500);
                    continue;
                }
            }

            // 3. Handle WebAuthn registration button
            var regBtn = await session.Page.QuerySelectorAsync("#registerWebAuthn, input[name='registerWebAuthn']");
            if (regBtn is not null && await regBtn.IsVisibleAsync())
            {
                await regBtn.ClickAsync();
                await Task.Delay(2000);
                continue;
            }

            // 4. Handle WebAuthn authentication button
            var authBtn = await session.Page.QuerySelectorAsync(
                "#authenticateWebAuthnButton, input[name='authenticateWebAuthnButton']");
            if (authBtn is not null && await authBtn.IsVisibleAsync())
            {
                await authBtn.ClickAsync();
                await Task.Delay(2000);
                continue;
            }

            // 5. Fast-fail on real server error banners
            var errorBanner = await session.Page.QuerySelectorAsync(
                ".alert-error, .alert-danger, .pf-m-danger, #input-error");
            if (errorBanner is not null)
            {
                var errorMsg = await errorBanner.TextContentAsync();
                if (!string.IsNullOrWhiteSpace(errorMsg) &&
                    !errorMsg.Contains("success", StringComparison.OrdinalIgnoreCase) &&
                    !errorMsg.Contains("Invalid username or password", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException($"Keycloak error: {errorMsg.Trim()}");
                }
            }

            await Task.Delay(250);
        }

        var pageBody = await session.Page.TextContentAsync("body") ?? "";
        throw new TimeoutException($"Callback not reached within 45s; final url={session.Page.Url}. Body: {pageBody[..Math.Min(400, pageBody.Length)]}");
    }

    private static async Task<string?> FindInteractiveStageAsync(IPage page)
    {
        try
        {
            var handle = await page.WaitForSelectorAsync(
                "#registerWebAuthn, #authenticateWebAuthnButton, #saveWebAuthn, #userLabel, input[name='userLabel'], input[name='authenticatorLabel'], #otp, #totp, #username",
                new PageWaitForSelectorOptions { State = WaitForSelectorState.Attached, Timeout = 400 });

            if (handle is null) return null;

            var id = await handle.GetAttributeAsync("id") ?? string.Empty;
            var name = await handle.GetAttributeAsync("name") ?? string.Empty;

            if (id == "registerWebAuthn" || name == "registerWebAuthn") return "register";
            if (id == "authenticateWebAuthnButton" || name == "authenticateWebAuthnButton") return "authenticate";
            if (id is "saveWebAuthn" or "userLabel" || name is "userLabel" or "authenticatorLabel") return "save_webauthn";
            if (id == "otp" || name == "otp") return "otp";
            if (id == "totp" || name == "totp") return "totp";
            if (id == "username" || name == "username") return "login";

            return null;
        }
        catch (TimeoutException)
        {
            return null;
        }
    }

    public static async Task<bool> WaitForErrorPageAsync(CeremonySession session)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                var body = await session.Page.TextContentAsync("body") ?? string.Empty;
                if (body.Contains("Invalid username or password", StringComparison.OrdinalIgnoreCase) ||
                    body.Contains("kc-feedback-text", StringComparison.OrdinalIgnoreCase) ||
                    body.Contains("alert-error", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            catch (PlaywrightException) { /* Page navigating; retry */ }

            await Task.Delay(200);
        }

        return false;
    }

    public static async Task<bool> WaitForLockoutMessageAsync(CeremonySession session)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                var body = await session.Page.TextContentAsync("body") ?? string.Empty;
                if (body.Contains("temporarily disabled", StringComparison.OrdinalIgnoreCase) ||
                    body.Contains("account is disabled", StringComparison.OrdinalIgnoreCase) ||
                    body.Contains("too many", StringComparison.OrdinalIgnoreCase) ||
                    body.Contains("locked", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            catch (PlaywrightException) { /* Page navigating; retry */ }

            await Task.Delay(200);
        }

        return false;
    }

    public static async Task<string> WaitForRegistrationErrorAsync(
        CeremonySession session, TimeSpan? timeout = null)
    {
        var deadline = DateTime.UtcNow.Add(timeout ?? TimeSpan.FromSeconds(20));

        while (DateTime.UtcNow < deadline)
        {
            var errorElement = await session.Page.QuerySelectorAsync(
                ".kc-feedback-text, .alert-error, .pf-c-alert__title");

            if (errorElement is not null)
            {
                var text = await errorElement.TextContentAsync();
                if (!string.IsNullOrWhiteSpace(text))
                    return text;
            }

            var url = session.Page.Url;
            if (url.Contains("/login-actions/required-action", StringComparison.Ordinal) ||
                url.Contains("/login-actions/authenticate", StringComparison.Ordinal))
            {
                var bodyText = await session.Page.TextContentAsync("body") ?? "";
                if (bodyText.Contains("invalid", StringComparison.OrdinalIgnoreCase) ||
                    bodyText.Contains("error", StringComparison.OrdinalIgnoreCase))
                    return bodyText;
            }

            await Task.Delay(250);
        }

        throw new TimeoutException(
            $"Registration error not detected within {timeout?.TotalSeconds ?? 20}s. URL: {session.Page.Url}");
    }

    public static async Task<TokenResponse> ExchangeCodeAsync(
        CeremonySession session, string code, CancellationToken ct = default)
        => await session.Client.ExchangeCodeForTokensAsync(code, session.CodeVerifier, ct: ct);

    // =========================================================================
    // MDS3 Mock Verification
    // =========================================================================

    public int Mds3FetchCount()
    {
        var log = Path.Combine(_accessLogDir, "access.log");
        if (!File.Exists(log))
        {
            return 0;
        }

        try
        {
            // Open with FileShare.ReadWrite | FileShare.Delete to read while Nginx holds the write lock
            using var stream = new FileStream(log, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream, Encoding.UTF8);
            var count = 0;
            while (reader.ReadLine() is { } line)
            {
                if (!string.IsNullOrWhiteSpace(line))
                {
                    count++;
                }
            }
            return count;
        }
        catch (IOException)
        {
            return 0;
        }
    }

    public async Task<string> ProbeMds3MockAsync(CancellationToken ct = default)
    {
        using var ca = X509Certificate2.CreateFromPem(
            await File.ReadAllTextAsync(Path.Combine(_artifactsDir, "ca.pem"), ct));

        using var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
            {
                if (cert is null) return false;
                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(ca);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                return chain.Build(new X509Certificate2(cert));
            }
        };

        using var http = new HttpClient(handler, disposeHandler: true) { Timeout = TimeSpan.FromSeconds(15) };
        using var response = await http.GetAsync($"https://{_mds3Mock.Hostname}:{Mds3PublicPort}/", ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync(ct);
    }

    // =========================================================================
    // Cryptographic Helpers
    // =========================================================================

    [SuppressMessage("Security", "CA5350",
        Justification = "RFC 6238 TOTP mandates HMAC-SHA1 for Keycloak OTP authenticator compatibility")]
    public static string ComputeTotp(string base32Secret, DateTimeOffset? utcNow = null)
    {
        var key = DecodeBase32(base32Secret);
        var timestep = (ulong)((utcNow ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds() / 30);

        Span<byte> counterBytes = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(counterBytes, timestep);

        using var hmac = new HMACSHA1(key);
        var hash = hmac.ComputeHash(counterBytes.ToArray());

        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24)
                     | (hash[offset + 1] << 16)
                     | (hash[offset + 2] << 8)
                     | hash[offset + 3];

        var otp = binary % 1_000_000;
        return otp.ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }

    // =========================================================================
    // Lifecycle
    // =========================================================================

    public async ValueTask InitializeAsync()
    {
        await _network.CreateAsync();
        try
        {
            await _mds3Mock.StartAsync();
            await _keycloak.StartAsync();
        }
        catch
        {
            await _mds3Mock.DisposeAsync();
            await _keycloak.DisposeAsync();
            await _network.DisposeAsync();
            throw;
        }

        _baseAddress = new UriBuilder(
            Uri.UriSchemeHttps,
            "localhost",
            _keycloak.GetMappedPublicPort(8443)).ToString().TrimEnd('/');

        await WaitForRealmReadyAsync();
        await RegisterAal3ClientAsync(RealmName);
        await RegisterAal3ClientAsync(Mds3RealmName);

        await CreateUserAsync(EnrollUsername, TestPassword, ["webauthn-register"]);
        await CreateUserAsync(AssertUsername, TestPassword, ["webauthn-register"]);

        // TotpUsername is pre-provisioned via sentinel-dast-aal3.json on container startup
        TotpSecret = FixedTotpSecret;

        await CreateUserAsync(LockoutUsername, TestPassword);
        await CreateUserAsync(BruteForceUsername, TestPassword);
        await CreateUserAsync(RogueUsername, TestPassword, ["webauthn-register"], Mds3RealmName);

        _playwright = await Microsoft.Playwright.Playwright.CreateAsync();
        _browser = await _playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
        {
            Headless = true,
            Args = ["--no-sandbox", "--disable-dev-shm-usage"]
        });

        _callbackServer = new CallbackServer(_callbackPort);
    }

    public async ValueTask DisposeAsync()
    {
        _callbackServer?.Dispose();
        _adminHttpClient?.Dispose();
        _adminLock.Dispose();

        if (_browser is not null)
            await _browser.CloseAsync();

        _playwright?.Dispose();
        await _keycloak.DisposeAsync();
        await _mds3Mock.DisposeAsync();
        await _network.DisposeAsync();

        try { Directory.Delete(_artifactsDir, recursive: true); }
        catch (IOException) { /* Windows file handles may outlive container teardown */ }
    }

    // =========================================================================
    // Private Helpers
    // =========================================================================

    private async Task RegisterAal3ClientAsync(string realm, CancellationToken ct = default)
    {
        var http = await GetAdminClientAsync(ct);

        using var flowsResponse = await http.GetAsync($"{_baseAddress}/admin/realms/{realm}/authentication/flows", ct);
        flowsResponse.EnsureSuccessStatusCode();
        using var flowsDoc = JsonDocument.Parse(await flowsResponse.Content.ReadAsStringAsync(ct));

        string? flowId = null;
        foreach (var flow in flowsDoc.RootElement.EnumerateArray())
        {
            if (flow.TryGetProperty("alias", out var alias) && alias.GetString() == Aal3BrowserFlow)
            {
                flowId = flow.GetProperty("id").GetString();
                break;
            }
        }

        var client = new JsonObject
        {
            ["clientId"] = Aal3ClientId,
            ["name"] = "Sentinel AAL3 WebAuthn test client",
            ["protocol"] = "openid-connect",
            ["publicClient"] = true,
            ["standardFlowEnabled"] = true,
            ["directAccessGrantsEnabled"] = true,
            ["implicitFlowEnabled"] = false,
            ["serviceAccountsEnabled"] = false,
            ["redirectUris"] = new JsonArray(RedirectUri),
            ["webOrigins"] = new JsonArray($"http://localhost:{_callbackPort}"),
            ["attributes"] = new JsonObject
            {
                ["pkce.code.challenge.method"] = "S256",
                ["dpop.bound.access.tokens"] = "true",
                ["require.pushed.authorization.requests"] = "true",
                ["access.token.signed.response.alg"] = "PS256",
                ["access.token.lifespan"] = "300"
            },
            ["protocolMappers"] = new JsonArray(
                new JsonObject
                {
                    ["name"] = "acr-claim",
                    ["protocol"] = "openid-connect",
                    ["protocolMapper"] = "oidc-hardcoded-claim-mapper",
                    ["consentRequired"] = false,
                    ["config"] = new JsonObject
                    {
                        ["access.token.claim"] = "true",
                        ["id.token.claim"] = "true",
                        ["claim.name"] = "acr",
                        ["claim.value"] = "acr3",
                        ["jsonType.label"] = "String"
                    }
                }
            ),
            ["defaultClientScopes"] = new JsonArray("roles", "profile", "email"),
            ["optionalClientScopes"] = new JsonArray("offline_access")
        };

        if (!string.IsNullOrEmpty(flowId))
        {
            client["authenticationFlowBindingOverrides"] = new JsonObject
            {
                ["browser"] = flowId
            };
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, $"{_baseAddress}/admin/realms/{realm}/clients")
        {
            Content = new StringContent(client.ToJsonString(), Encoding.UTF8, "application/json")
        };

        using var response = await http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
    }

    private static void CreateRealmVariants(string artifactsDir)
    {
        var stockPath = Path.Combine(GetRepoRoot(), "infra", "keycloak", "realms", "sentinel-dast.json");
        var stock = JsonNode.Parse(File.ReadAllText(stockPath))!;

        var aal3 = stock.DeepClone()!;
        if (aal3["attributes"] is JsonObject attrs)
        {
            attrs["webAuthnPolicyAttestationConveyancePreference"] = "none";
            attrs["acr.loa.map"] = "{\"acr3\":3,\"3\":3,\"acr2\":2,\"2\":2,\"acr1\":1,\"1\":1,\"government-aal3-browser\":3}";
        }
        aal3["browserFlow"] = Aal3BrowserFlow;

        if (aal3["requiredActions"] is JsonArray actions)
        {
            foreach (var action in actions.OfType<JsonObject>())
            {
                if (action["alias"]?.GetValue<string>() == "CONFIGURE_TOTP")
                    action["enabled"] = true;
                if (action["alias"]?.GetValue<string>() == "webauthn-register")
                {
                    action["enabled"] = true;
                    action["defaultAction"] = false;
                }
            }
        }

        // Configure gov-aal3-forms: Password (REQUIRED) + WebAuthn (ALTERNATIVE) + OTP Recovery (ALTERNATIVE)
        if (aal3["authenticationFlows"] is JsonArray flows)
        {
            foreach (var flow in flows.OfType<JsonObject>())
            {
                if (flow["alias"]?.GetValue<string>() == "gov-aal3-forms")
                {
                    flow["authenticationExecutions"] = new JsonArray(
                        new JsonObject
                        {
                            ["authenticator"] = "auth-username-password-form",
                            ["requirement"] = "REQUIRED",
                            ["priority"] = 10,
                            ["userSetupAllowed"] = false,
                            ["autheticatorFlow"] = false
                        },
                        new JsonObject
                        {
                            ["authenticator"] = "webauthn-authenticator",
                            ["requirement"] = "ALTERNATIVE",
                            ["priority"] = 20,
                            ["userSetupAllowed"] = false,
                            ["autheticatorFlow"] = false
                        },
                        new JsonObject
                        {
                            ["requirement"] = "ALTERNATIVE",
                            ["priority"] = 30,
                            ["flowAlias"] = "gov-aal3-otp-recovery",
                            ["userSetupAllowed"] = false,
                            ["autheticatorFlow"] = true
                        }
                    );
                }
            }
        }

        // Pre-provision aal3-totp-user in the realm JSON with valid OTP credentials
        var totpUser = new JsonObject
        {
            ["username"] = TotpUsername,
            ["enabled"] = true,
            ["email"] = $"{TotpUsername}@sentinel.test",
            ["emailVerified"] = true,
            ["realmRoles"] = new JsonArray("user"),
            ["credentials"] = new JsonArray(
                new JsonObject
                {
                    ["type"] = "password",
                    ["value"] = TestPassword,
                    ["temporary"] = false
                },
                new JsonObject
                {
                    ["type"] = "otp",
                    ["userLabel"] = "aal3-test-totp",
                    ["secretData"] = JsonSerializer.Serialize(new { value = FixedTotpSecret }),
                    ["credentialData"] = JsonSerializer.Serialize(new { subType = "totp", digits = 6, counter = 0, period = 30, algorithm = "HmacSHA1" }),
                    ["temporary"] = false
                }
            ),
            ["requiredActions"] = new JsonArray()
        };

        if (aal3["users"] is JsonArray users)
        {
            users.Add(totpUser);
        }
        else
        {
            aal3["users"] = new JsonArray(totpUser);
        }

        File.WriteAllText(Path.Combine(artifactsDir, "sentinel-dast-aal3.json"), aal3.ToJsonString());

        var mds3 = stock.DeepClone()!;
        mds3["realm"] = Mds3RealmName;
        File.WriteAllText(Path.Combine(artifactsDir, "sentinel-dast-mds3.json"), mds3.ToJsonString());
    }

    private async Task WaitForRealmReadyAsync()
    {
        using var http = CreateTrustingHttpClient();
        var deadline = DateTime.UtcNow.AddSeconds(300);
        var lastError = string.Empty;

        foreach (var realm in new[] { RealmName, Mds3RealmName })
        {
            var ready = false;
            while (DateTime.UtcNow < deadline && !ready)
            {
                try
                {
                    using var response = await http.GetAsync(
                        $"{_baseAddress}/realms/{realm}/.well-known/openid-configuration");
                    if (response.IsSuccessStatusCode)
                    {
                        ready = true;
                        continue;
                    }
                    lastError = $"discovery for {realm} returned {response.StatusCode}";
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    lastError = ex.Message;
                }

                await Task.Delay(1000);
            }

            if (!ready)
                throw new TimeoutException($"Keycloak realm {realm} not ready within 300s: {lastError}");
        }
    }

    [SuppressMessage("Reliability", "CA2000",
        Justification = "Handler is a static singleton; disposed at process exit")]
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
            chain.ChainPolicy.VerificationTime = cert.NotBefore.AddHours(1);
            return chain.Build(cert);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    [SuppressMessage("Reliability", "CA2000",
        Justification = "Shared handler; callers manage HttpClient lifetime")]
    public static HttpClient CreateTrustingHttpClient()
        => new(SentinelCaHandler.Value, disposeHandler: false) { Timeout = TimeSpan.FromSeconds(30) };

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

    private static async Task<string> ReadBodyAsync(IPage page)
    {
        try { return await page.TextContentAsync("body") ?? string.Empty; }
        catch (PlaywrightException) { return string.Empty; }
    }

    private static byte[] DecodeBase32(string input)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var clean = input.ToUpperInvariant().Where(alphabet.Contains).ToArray();
        var output = new List<byte>();
        var buffer = 0;
        var bitsLeft = 0;

        foreach (var c in clean)
        {
            var val = alphabet.IndexOf(c);
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                bitsLeft -= 8;
                output.Add((byte)((buffer >> bitsLeft) & 0xFF));
                buffer &= (1 << bitsLeft) - 1; // Clear consumed bits so buffer never overflows
            }
        }
        return output.ToArray();
    }

    private static string GetRepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Sentinel.slnx")))
            directory = directory.Parent;

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


    private static void GenerateMds3Artifacts(string dir, string accessLogDir)
    {
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1).UtcDateTime;
        var notAfter = DateTimeOffset.UtcNow.AddYears(5).UtcDateTime;

        using var caKey = RSA.Create(2048);
        var caRequest = new CertificateRequest(
            "CN=Sentinel MDS3 Mock CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, false));
        using var caCert = caRequest.CreateSelfSigned(notBefore, notAfter);

        using var leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest(
            "CN=mds3.fidoalliance.org", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("mds3.fidoalliance.org");
        leafRequest.CertificateExtensions.Add(san.Build());
        leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
        leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));
        using var leafCert = leafRequest.Create(caCert, notBefore, notAfter, RandomNumberGenerator.GetBytes(16));

        File.WriteAllText(Path.Combine(dir, "tls.crt"), leafCert.ExportCertificatePem());
        File.WriteAllText(Path.Combine(dir, "tls.key"), leafKey.ExportPkcs8PrivateKeyPem());
        File.WriteAllText(Path.Combine(dir, "ca.pem"), caCert.ExportCertificatePem());

        var caCertOnly = X509CertificateLoader.LoadCertificate(caCert.Export(X509ContentType.Cert));
        File.WriteAllBytes(Path.Combine(dir, "mds3-truststore.p12"),
            caCertOnly.Export(X509ContentType.Pfx, TruststorePassword));

        File.WriteAllText(Path.Combine(dir, "blob.jwt"), BuildMds3Blob(caCert, caKey));
        File.WriteAllText(Path.Combine(dir, "nginx.conf"), BuildNginxConf());

        Directory.CreateDirectory(accessLogDir);
        File.WriteAllText(Path.Combine(accessLogDir, "access.log"), string.Empty);
    }

    private static string BuildMds3Blob(X509Certificate2 caCert, RSA caKey)
    {
        const string aaguid = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a";
        var header = new Dictionary<string, object>
        {
            ["alg"] = "RS256",
            ["typ"] = "JWT",
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        var metadataStatement = new Dictionary<string, object>
        {
            ["aaguid"] = aaguid,
            ["description"] = "Sentinel hermetic test authenticator (MDS3 mock)",
            ["authenticatorVersion"] = 1,
            ["protocolFamily"] = "fido2",
            ["upv"] = new[] { new { major = 1, minor = 0 } },
            ["assertionSchemes"] = new[] { "FIDO2" },
            ["authenticationAlgorithms"] = new[] { new { type = "public-key", alg = -7 } },
            ["publicKeyAlgAndEncodings"] = new[] { "cose" },
            ["attestationTypes"] = new[] { "basic_full" },
            ["userVerificationDetails"] = new[]
            {
                new[] { new { userVerificationMethod = "passcode_internal" } },
                new[] { new { userVerificationMethod = "presence_internal" } }
            },
            ["keyProtection"] = new[] { "hardware", "secure_element" },
            ["matcherProtection"] = new[] { "on_chip" },
            ["attachmentHint"] = new[] { "internal" },
            ["isSecondFactorOnly"] = false,
            ["tcDisplay"] = false,
            ["attestationRootCertificates"] = new[] { caCert.ExportCertificatePem() }
        };

        var payload = new Dictionary<string, object>
        {
            ["no"] = 1,
            ["at"] = "2026-01-01",
            ["payload"] = new object(),
            ["entries"] = new[]
            {
                new Dictionary<string, object>
                {
                    ["aaguid"] = aaguid,
                    ["statusReports"] = new[] { new { status = "FIDO_CERTIFIED", effectiveDate = "2026-01-01" } },
                    ["metadataStatement"] = metadataStatement
                }
            },
            ["validFrom"] = "2026-01-01",
            ["validUntil"] = "2099-12-31"
        };

        var headerB64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header)));
        var payloadB64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));
        var signature = caKey.SignData(
            Encoding.ASCII.GetBytes($"{headerB64}.{payloadB64}"),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{headerB64}.{payloadB64}.{Base64UrlEncoder.Encode(signature)}";
    }

    private static string BuildNginxConf() => """
        server {
            listen 443 ssl;
            server_name mds3.fidoalliance.org;
            ssl_certificate /etc/nginx/tls/tls.crt;
            ssl_certificate_key /etc/nginx/tls/tls.key;
            access_log /var/log/nginx/access.log;
            error_log /var/log/nginx/error.log warn;
            root /usr/share/nginx/html;
            index index.html;
        }
        """;
}