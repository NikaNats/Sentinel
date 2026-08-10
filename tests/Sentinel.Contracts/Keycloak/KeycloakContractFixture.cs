using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using DotNet.Testcontainers.Builders;
using Testcontainers.Keycloak;

namespace Sentinel.Contracts.Keycloak;

/// <summary>
///     Contract test fixture: boots a REAL Keycloak 26.6.4 container (the image
///     pinned by the repo's base compose) and captures the exact OIDC surface.
///
///     SECURITY: no mocks, no TestAuthHandler. Every assertion validates the
///     REAL Keycloak wire format that Microsoft.IdentityModel talks to.
///
///     DEVIATION FROM CONTRACT-001 GUIDE:
///     * Image 26.1 --&gt; 26.6.4 (repo pinned base image).
///     * The dev realm's sentinel-api-client authenticates with client-jwt
///       (private_key_jwt), so client-secret based token tests use a dedicated
///       contract client created via the Admin API on initialization.
/// </summary>
public sealed class KeycloakContractFixture : IAsyncLifetime
{
    public const string RealmName = "sentinel";
    public const string ContractClientId = "sentinel-contract-client";
    public const string ContractClientSecret = "contract-test-secret";

    private readonly KeycloakContainer _keycloak;
    private string _baseAddress = string.Empty;

    public KeycloakContractFixture()
    {
        var repoRoot = GetRepoRoot();
        _keycloak = new KeycloakBuilder("quay.io/keycloak/keycloak:26.6.4")
            .WithUsername("admin")
            .WithPassword("contract-test-admin")
            .WithEnvironment("KC_FEATURES", "dpop,par")
            // Mirror the repo compose keycloak service (docker-compose.yml):
            // HTTPS-only on 8443 with the repo-local CA/cert pair. The imported
            // realm sets "sslRequired": "all", so plain HTTP would be refused
            // with 403 - HTTPS is the REAL wire format the app talks.
            .WithEnvironment("KC_HEALTH_ENABLED", "true")
            .WithEnvironment("KC_HTTP_ENABLED", "false")
            .WithEnvironment("KC_HTTPS_PORT", "8443")
            .WithEnvironment("KC_HTTPS_CERTIFICATE_FILE", "/etc/x509/certs/keycloak.crt")
            .WithEnvironment("KC_HTTPS_CERTIFICATE_KEY_FILE", "/etc/x509/keys/keycloak.key")
            .WithPortBinding(8443, true)
            // Testcontainers' WithCommand APPENDS to the pre-configured
            // `start-dev` command, so use the module's WithRealm() (appends
            // `--import-realm` and maps the realm file world-readable; the
            // container runs as UID 1000 and cannot read a root-owned 0400).
            // The module's default wait strategy polls /health/ready on port 9000 over
            // plain HTTP - with KC_HTTP_ENABLED=false the management interface
            // is HTTPS-only and that check would burn its 10-minute timeout.
            // Wait on the startup log line instead; readiness is then verified
            // by the fixture's own HTTPS discovery poll.
            .WithWaitStrategy(Wait.ForUnixContainer()
                .UntilMessageIsLogged("Keycloak .* started in .*"))
            .WithRealm(Path.Combine(repoRoot, "infra", "keycloak", "realms", "sentinel.json"))
            // Resource mappings land as directories (the file keeps its
            // basename inside), so mount into separate directories and point
            // the KC_HTTPS_* variables at the actual paths.
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

    public Uri DiscoveryUrl => new($"{RealmUrl}/.well-known/openid-configuration");

    public string TokenEndpoint => $"{RealmUrl}/protocol/openid-connect/token";

    public Uri JwksUri => new($"{RealmUrl}/protocol/openid-connect/certs");

    public Uri AdminBaseUrl => new($"{_baseAddress}/admin/realms/{RealmName}");

    public string AdminToken { get; private set; } = string.Empty;

    public HttpClient HttpClient { get; private set; } = null!;

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability", "CA2000",
        Justification = "HttpClient (and its handler, disposed via disposeHandler: true) lives for the fixture's lifetime and is disposed in DisposeAsync.")]
    public async ValueTask InitializeAsync()
    {
        await _keycloak.StartAsync();
        // Keycloak in this posture serves HTTPS 8443 only; GetBaseAddress()
        // (plain HTTP on 8080) is unusable. Build the TLS address from the
        // mapped 8443 port instead.
        _baseAddress = new UriBuilder(
            Uri.UriSchemeHttps,
            _keycloak.Hostname,
            _keycloak.GetMappedPublicPort(8443)).ToString().TrimEnd('/');

        HttpClient = new HttpClient(CreateTrustingHandler(true), disposeHandler: true)
        {
            Timeout = TimeSpan.FromSeconds(30)
        };

        await WaitForRealmReadyAsync();
        AdminToken = await AcquireAdminTokenAsync();
        await CreateContractClientAsync();
        await CreateContractUserAsync();
    }

    public async ValueTask DisposeAsync()
    {
        HttpClient.Dispose();
        await _keycloak.DisposeAsync();
    }

    /// <summary>Admin-API authenticated request helper.</summary>
    public async Task<HttpResponseMessage> SendAdminAsync(HttpMethod method, string path,
        HttpContent? content = null, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(method, $"{AdminBaseUrl}{path}");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", AdminToken);
        request.Content = content;
        return await HttpClient.SendAsync(request, cancellationToken);
    }

    private async Task<string> AcquireAdminTokenAsync()
    {
        using var adminBody = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "admin-cli",
            ["username"] = "admin",
            ["password"] = "contract-test-admin"
        });
        var response = await HttpClient.PostAsync(
            $"{_baseAddress}/realms/master/protocol/openid-connect/token",
            adminBody);

        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.GetProperty("access_token").GetString()
            ?? throw new InvalidOperationException("Admin token was not issued.");
    }

    private static readonly string FixtureLogPath =
        Path.Combine(Path.GetTempPath(), "opencode", "kc-fixture.log");

    private static void Log(string message)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FixtureLogPath)!);
            File.AppendAllText(FixtureLogPath, $"{DateTime.UtcNow:O} {message}{Environment.NewLine}");
        }
        catch (IOException)
        {
            // best effort
        }
        catch (UnauthorizedAccessException)
        {
            // best effort
        }
        catch (System.Security.SecurityException)
        {
            // best effort
        }
    }

    private async Task WaitForRealmReadyAsync()
    {
        var deadline = DateTime.UtcNow.AddSeconds(300);
        var attempt = 0;
        while (DateTime.UtcNow < deadline)
        {
            attempt++;
            try
            {
                var response = await HttpClient.GetAsync(DiscoveryUrl);
                if (response.IsSuccessStatusCode)
                {
                    Log($"[KeycloakFixture] Attempt {attempt}: Discovery 200 OK: {DiscoveryUrl}");
                    return;
                }
                Log($"[KeycloakFixture] Attempt {attempt}: Discovery returned {response.StatusCode}: {DiscoveryUrl}");
                Console.WriteLine($"[KeycloakFixture] Attempt {attempt}: Discovery endpoint returned {response.StatusCode}");
            }
            catch (HttpRequestException ex)
            {
                Log($"[KeycloakFixture] Attempt {attempt}: HTTP error - {ex.Message}");
                Console.WriteLine($"[KeycloakFixture] Attempt {attempt}: HTTP error - {ex.Message}");
            }
            catch (TaskCanceledException ex)
            {
                Log($"[KeycloakFixture] Attempt {attempt}: Request timeout - {ex.Message}");
                Console.WriteLine($"[KeycloakFixture] Attempt {attempt}: Request timeout - {ex.Message}");
            }

            await Task.Delay(1000);
        }

        // Dump container logs on timeout
        try
        {
            var logs = await _keycloak.GetLogsAsync();
            Log($"===== KEYCLOAK STDOUT =====\n{logs.Stdout}\n===== KEYCLOAK STDERR =====\n{logs.Stderr}");
            Console.WriteLine("===== KEYCLOAK STDOUT =====");
            Console.WriteLine(logs.Stdout);
            Console.WriteLine("===== KEYCLOAK STDERR =====");
            Console.WriteLine(logs.Stderr);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log($"[KeycloakFixture] Failed to get container logs: {ex.Message}");
            Console.WriteLine($"[KeycloakFixture] Failed to get container logs: {ex.Message}");
        }

        throw new TimeoutException("Keycloak realm was not ready within 300 seconds");
    }

    private async Task CreateContractClientAsync()
    {
        var payload = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["clientId"] = ContractClientId,
            ["protocol"] = "openid-connect",
            ["enabled"] = true,
            ["publicClient"] = false,
            ["serviceAccountsEnabled"] = true,
            ["directAccessGrantsEnabled"] = false,
            ["standardFlowEnabled"] = true,
            ["redirectUris"] = new[] { "https://contract.sentinel.local/callback" },
            ["clientAuthenticatorType"] = "client-secret",
            ["secret"] = ContractClientSecret,
            ["attributes"] = new Dictionary<string, string>
            {
                ["use.refresh.tokens"] = "true",
                ["refresh.token.max.reuse"] = "0",
                ["access.token.lifespan"] = "300",
                ["client.session.idle.timeout"] = "1800",
                ["client.session.max.lifespan"] = "28800"
            },
            ["protocolMappers"] = new[]
            {
                new Dictionary<string, object?>
                {
                    ["name"] = "audience-sentinel-api",
                    ["protocol"] = "openid-connect",
                    ["protocolMapper"] = "oidc-audience-mapper",
                    ["consentRequired"] = false,
                    ["config"] = new Dictionary<string, string>
                    {
                        ["included.custom.audience"] = "sentinel-api",
                        ["access.token.claim"] = "true",
                        ["id.token.claim"] = "false"
                    }
                }
            }
        });

        using var content = new StringContent(payload, System.Text.Encoding.UTF8, "application/json");
        var response = await SendAdminAsync(HttpMethod.Post, "/clients", content);
        response.StatusCode.Should().Be(HttpStatusCode.Created, "contract client must be provisioned via Admin API");
    }

    /// <summary>
    ///     Performs the REAL interactive login: authorization-code flow with
    ///     PKCE S256, the Keycloak login form, and a DPoP-bound token exchange.
    ///     This is Constitution-faithful (ROPC is prohibited, so sessions can
    ///     only come from this path).
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability", "CA2000",
        Justification = "The browser HttpClient disposes its handler via disposeHandler: true and is itself disposed by the enclosing using declaration.")]
    public async Task<TokenResponseContract> LoginInteractiveAsync()
    {
        const string redirectUri = "https://contract.sentinel.local/callback";
        var verifier = GeneratePkceVerifier();
        var challenge = S256Challenge(verifier);
        var state = Guid.NewGuid().ToString("N");
        var nonce = Guid.NewGuid().ToString("N");

        var authorizeUrl =
            $"{RealmUrl}/protocol/openid-connect/auth?response_type=code" +
            $"&client_id={ContractClientId}" +
            $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
            $"&state={state}&nonce={nonce}&scope=openid" +
            $"&code_challenge={challenge}&code_challenge_method=S256";

        // Redirects are followed manually here: the authorize hop may 200 or
        // 302, and the final callback must be inspected, not fetched
        // (https://contract.sentinel.local is not real).
        using var browser = new HttpClient(CreateTrustingHandler(false), disposeHandler: true) { Timeout = TimeSpan.FromSeconds(30) };

        using (var authorize = await browser.GetAsync(authorizeUrl))
        {
            string loginPageHtml = authorize.StatusCode switch
            {
                // Keycloak 26 answers the authorize request directly with the
                // rendered login form (200) instead of redirecting to it (302).
                HttpStatusCode.OK => await authorize.Content.ReadAsStringAsync(),
                HttpStatusCode.Found => await FollowToLoginPageAsync(browser, authorize),
                _ => throw new InvalidOperationException($"authorize returned {authorize.StatusCode}")
            };

            var (action, clientData) = ExtractLoginFormAction(loginPageHtml);

            using var loginRequest = new HttpRequestMessage(HttpMethod.Post, action)
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["username"] = "contract-user",
                    ["password"] = "ContractTest123!",
                    ["credentialId"] = string.Empty,
                    ["client_data"] = clientData
                })
            };

            using var login = await browser.SendAsync(loginRequest);

            login.StatusCode.Should().Be(HttpStatusCode.Found, "login must redirect back to the client");
            var callback = login.Headers.Location!.ToString();
            callback.Should().StartWith(redirectUri, "redirect must return to the registered callback");

            var callbackQuery = ParseQueryString(new Uri(callback).Query);
            callbackQuery["state"].Should().Be(state, "OAuth state must round-trip (CSRF guard)");
            var code = callbackQuery["code"];
            code.Should().NotBeNullOrWhiteSpace("authorization code must be issued");

            using var exchangeRequest = new HttpRequestMessage(HttpMethod.Post, TokenEndpoint)
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "authorization_code",
                    ["code"] = code,
                    ["redirect_uri"] = redirectUri,
                    ["client_id"] = ContractClientId,
                    ["client_secret"] = ContractClientSecret,
                    ["code_verifier"] = verifier
                })
            };
            exchangeRequest.Headers.Add("DPoP", DpopProofBuilder.CreateProof(TokenEndpoint));
            using var exchange = await browser.SendAsync(exchangeRequest);

            exchange.StatusCode.Should().Be(HttpStatusCode.OK, "DPoP-bound code exchange must succeed");
            var json = await exchange.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<TokenResponseContract>(json)
                ?? throw new InvalidOperationException("Token response was not parseable.");
        }
    }

    private static async Task<string> FollowToLoginPageAsync(HttpClient browser, HttpResponseMessage authorize)
    {
        using var loginPage = await browser.GetAsync(authorize.Headers.Location!);
        loginPage.StatusCode.Should().Be(HttpStatusCode.OK, "login form must render");
        return await loginPage.Content.ReadAsStringAsync();
    }

    private static Dictionary<string, string> ParseQueryString(string query)
    {
        var result = new Dictionary<string, string>();
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

    private static string GeneratePkceVerifier()
    {
        var bytes = RandomNumberGenerator.GetBytes(48);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string S256Challenge(string verifier)
    {
        using var sha256 = SHA256.Create();
        var digest = sha256.ComputeHash(System.Text.Encoding.ASCII.GetBytes(verifier));
        return Convert.ToBase64String(digest).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static (string Action, string ClientData) ExtractLoginFormAction(string html)
    {
        const string marker = "id=\"kc-form-login\"";
        var formIndex = html.IndexOf(marker, StringComparison.Ordinal);
        formIndex.Should().BeGreaterThan(-1, "login form must be present");
        var actionStart = html.IndexOf("action=\"", formIndex, StringComparison.Ordinal);
        actionStart.Should().BeGreaterThan(-1, "login form must carry a POST action");
        actionStart += "action=\"".Length;
        var actionEnd = html.IndexOf('"', actionStart);
        var action = System.Net.WebUtility.HtmlDecode(html[actionStart..actionEnd]);

        var actionQuery = ParseQueryString(new Uri(action).Query);
        actionQuery.TryGetValue("client_data", out var clientData);

        return (action, clientData ?? string.Empty);
    }

    private async Task CreateContractUserAsync()
    {
        var payload = JsonSerializer.Serialize(new
        {
            username = "contract-user",
            enabled = true,
            emailVerified = true,
            email = "contract-user@contract-test.local",
            credentials = new[]
            {
                new { type = "password", value = "ContractTest123!", temporary = false }
            }
        });

        using var content = new StringContent(payload, System.Text.Encoding.UTF8, "application/json");
        var response = await SendAdminAsync(HttpMethod.Post, "/users", content);
        response.StatusCode.Should().Be(HttpStatusCode.Created, "contract user must be provisioned via Admin API");
    }

    /// <summary>
    ///     Trusts only certificates signed by the repo-local Sentinel CA
    ///     (infra/certs/ca.crt) - the same CA the keycloak container cert
    ///     chains to, and the same CA the API trusts via Keycloak__TrustedCaPath.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability", "CA2000",
        Justification = "The CA certificate must outlive the returned handler: its validation callback and the handler's CustomTrustStore reference it for the lifetime of every HTTP client created in this fixture; the clients are disposed in DisposeAsync.")]
    private static HttpClientHandler CreateTrustingHandler(bool followRedirects)
    {
        var ca = X509Certificate2.CreateFromPem(
            File.ReadAllText(Path.Combine(GetRepoRoot(), "infra", "certs", "ca.crt")));
        return new HttpClientHandler
        {
            AllowAutoRedirect = followRedirects,
            ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
                cert is not null && IsSignedBySentinelCa(cert, ca)
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
            // The repo-issued certs were generated with a slightly forward
            // NotBefore (clock drift at generation time). Evaluate the chain
            // within the validity window so the CA pin is what's asserted.
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

[CollectionDefinition(Name)]
public sealed class KeycloakContractCollection : ICollectionFixture<KeycloakContractFixture>
{
    public const string Name = "Keycloak Contract";
}

/// <summary>Minimal token response used for admin token acquisition.</summary>
public sealed record TokenResponseContract(
    [property: System.Text.Json.Serialization.JsonPropertyName("access_token")]
    string AccessToken,
    [property: System.Text.Json.Serialization.JsonPropertyName("token_type")]
    string TokenType,
    [property: System.Text.Json.Serialization.JsonPropertyName("expires_in")]
    int ExpiresIn,
    [property: System.Text.Json.Serialization.JsonPropertyName("refresh_token")]
    string? RefreshToken);