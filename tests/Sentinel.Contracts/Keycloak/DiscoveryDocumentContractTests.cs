using System.Net;
using System.Text.Json;
using Sentinel.Contracts.Shared;

namespace Sentinel.Contracts.Keycloak;

/// <summary>
///     CONTRACT: OIDC Discovery Document Shape.
///
///     Pins the exact structure the .NET
///     <c>ConfigurationManager&lt;OpenIdConnectConfiguration&gt;</c> depends on.
///     A missing or renamed field silently breaks token validation; this suite
///     turns that drift into an immediate build failure.
///
///     Constitution Ref: §II.1 (OIDC Full Activation), §IV.1 (Signing Algorithms).
/// </summary>
[Collection(KeycloakContractCollection.Name)]
[ContractVersion("CONTRACT-001", "1.0", Target = "Keycloak 26.6.4")]
public sealed class DiscoveryDocumentContractTests(KeycloakContractFixture fixture)
{
    private readonly KeycloakContractFixture _fixture = fixture;

    [Theory(DisplayName = "CONTRACT: discovery contains required OIDC endpoint URLs")]
    [InlineData("issuer")]
    [InlineData("authorization_endpoint")]
    [InlineData("token_endpoint")]
    [InlineData("jwks_uri")]
    [InlineData("userinfo_endpoint")]
    [InlineData("end_session_endpoint")]
    [InlineData("introspection_endpoint")]
    [InlineData("revocation_endpoint")]
    public async Task DiscoveryDocument_ContainsRequiredEndpoint(string field)
    {
        var json = await FetchDiscoveryDocumentAsync();

        var hasField = json.TryGetProperty(field, out var value);

        hasField.Should().BeTrue($"discovery MUST contain '{field}' (breaks Microsoft.IdentityModel)");
        value.ValueKind.Should().Be(JsonValueKind.String, $"'{field}' must be a string");
        value.GetString().Should().NotBeNullOrWhiteSpace();
        value.GetString()!.Should().StartWith("http", $"'{field}' must be an absolute URL");
    }

    [Fact(DisplayName = "CONTRACT: discovery 'issuer' matches realm URL exactly")]
    public async Task DiscoveryDocument_Issuer_MatchesRealmUrl()
    {
        var json = await FetchDiscoveryDocumentAsync();

        json.GetProperty("issuer").GetString().Should().Be(
            _fixture.RealmUrl.ToString(),
            "issuer must match the Keycloak authority URL exactly (IDX10205 otherwise)");
    }

    [Fact(DisplayName = "CONTRACT: discovery validates against the pinned JSON Schema")]
    public async Task DiscoveryDocument_ValidatesAgainstPinnedSchema()
    {
        var json = await FetchDiscoveryDocumentAsync();
        var schema = EmbeddedResourceReader.Read("discovery-document.schema.json");

        var result = SchemaValidator.Validate(schema, json.GetRawText());

        result.IsValid.Should().BeTrue(
            $"discovery drifted from the pinned schema:{Environment.NewLine}{string.Join(Environment.NewLine, result.Errors)}");
    }

    [Fact(DisplayName = "CONTRACT: PAR endpoint advertised (FAPI 2.0 mandatory)")]
    public async Task DiscoveryDocument_ContainsPushedAuthorizationRequestEndpoint()
    {
        var json = await FetchDiscoveryDocumentAsync();

        var hasPar = json.TryGetProperty("pushed_authorization_request_endpoint", out var parValue);

        hasPar.Should().BeTrue("FAPI 2.0 requires pushed_authorization_request_endpoint");
        parValue.GetString().Should().Contain("/ext/par/request", "PAR path structure must be stable");
    }

    [Fact(DisplayName = "CONTRACT: discovery advertises DPoP with PS256/ES256 supported")]
    public async Task DiscoveryDocument_AdvertisesDpopSupport()
    {
        var json = await FetchDiscoveryDocumentAsync();

        var hasDpop = json.TryGetProperty("dpop_signing_alg_values_supported", out var dpopAlgs);
        hasDpop.Should().BeTrue("FAPI 2.0 requires dpop_signing_alg_values_supported");

        var algs = dpopAlgs.EnumerateArray().Select(e => e.GetString()).ToList();

        // Keycloak 26.6.4 advertises its FULL static algorithm surface (RS256,
        // HS256...). The Constitution's algorithm enforcement is pinned in
        // DiscoveryDocument_Fapi2Enforcement_MatchesConstitution instead.
        algs.Should().Contain("PS256", "PS256 must be supported for DPoP (Constitution §IV.1)");
        algs.Should().Contain("ES256", "ES256 must be supported for DPoP (Constitution §IV.1)");
    }

    [Fact(DisplayName = "CONTRACT: token endpoint supports required grant types")]
    public async Task DiscoveryDocument_TokenEndpoint_SupportsRequiredGrantTypes()
    {
        var json = await FetchDiscoveryDocumentAsync();

        var grantTypes = json.GetProperty("grant_types_supported")
            .EnumerateArray().Select(e => e.GetString()).ToList();

        grantTypes.Should().Contain("authorization_code", "primary interactive flow");
        grantTypes.Should().Contain("refresh_token", "session management");
        grantTypes.Should().Contain("client_credentials", "M2M service accounts");
    }

    [Fact(DisplayName = "CONTRACT: PKCE S256 is advertised")]
    public async Task DiscoveryDocument_PkceS256_Supported()
    {
        var json = await FetchDiscoveryDocumentAsync();

        var methods = json.GetProperty("code_challenge_methods_supported")
            .EnumerateArray().Select(e => e.GetString()).ToList();

        methods.Should().Contain("S256", "PKCE S256 is MANDATORY (§II.1, FAPI 2.0)");
    }

    [Fact(DisplayName = "CONTRACT: private_key_jwt token auth advertised, 'none' absent")]
    public async Task DiscoveryDocument_TokenEndpointAuth_IncludesPrivateKeyJwt()
    {
        var json = await FetchDiscoveryDocumentAsync();

        var authMethods = json.GetProperty("token_endpoint_auth_methods_supported")
            .EnumerateArray().Select(e => e.GetString()).ToList();

        authMethods.Should().Contain("private_key_jwt", "confidential clients MUST use JWT auth (§II.4)");
        authMethods.Should().NotContain("none", "unauthenticated token requests are PROHIBITED");
    }

    [Fact(DisplayName = "CONTRACT: PS256 is advertised for ID token signing")]
    public async Task DiscoveryDocument_IdTokenSigningAlgorithms_Ps256Advertised()
    {
        var json = await FetchDiscoveryDocumentAsync();

        var algs = json.GetProperty("id_token_signing_alg_values_supported")
            .EnumerateArray().Select(e => e.GetString()).ToList();

        // Keycloak 26.6.4 advertises a static list that includes RS*/HS* algs;
        // what the realm will actually sign with is pinned at the enforcement
        // layer (DiscoveryDocument_Fapi2Enforcement_MatchesConstitution + the
        // token/JWKS tests assert PS256 on the wire).
        algs.Should().Contain("PS256", "PS256 is the PRIMARY signing algorithm (§IV.1)");
    }

    [Fact(DisplayName = "CONTRACT: back-channel logout advertised")]
    public async Task DiscoveryDocument_AdvertisesBackchannelLogout()
    {
        var json = await FetchDiscoveryDocumentAsync();

        json.TryGetProperty("backchannel_logout_supported", out var supported).Should().BeTrue(
            "back-channel logout is required (§II.1)");
        supported.GetBoolean().Should().BeTrue();

        if (json.TryGetProperty("backchannel_logout_session_supported", out var sessionSupported))
        {
            sessionSupported.GetBoolean().Should().BeTrue("session-based logout required");
        }
    }

    [Fact(DisplayName = "CONTRACT: response types include the Authorization Code flow")]
    public async Task DiscoveryDocument_ResponseTypes_IncludeCode()
    {
        var json = await FetchDiscoveryDocumentAsync();

        var responseTypes = json.GetProperty("response_types_supported")
            .EnumerateArray().Select(e => e.GetString()).ToList();

        responseTypes.Should().Contain("code", "Authorization Code flow is primary");
    }

    [Fact(DisplayName = "CONTRACT: FAPI 2.0 enforcement matches the Constitution")]
    public async Task DiscoveryDocument_Fapi2Enforcement_MatchesConstitution()
    {
        // Keycloak 26.6.4 serves a STATIC discovery surface: 'implicit' and
        // 'password' grants, PKCE 'plain' and RS*/HS* algs are always advertised.
        // The Constitution's prohibitions are therefore pinned at the layer
        // where Keycloak actually enforces them: realm client policies,
        // client flags and the active signing-key set.

        var realmResponse = await _fixture.SendAdminAsync(HttpMethod.Get, string.Empty, cancellationToken: TestContext.Current.CancellationToken);
        realmResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        using var realmDoc = JsonDocument.Parse(await realmResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var realm = realmDoc.RootElement;

        // Realm policies: exactly one FAPI policy, enabled, applied to every client.
        var policies = realm.GetProperty("clientPolicies").GetProperty("policies").EnumerateArray().ToList();
        policies.Should().ContainSingle("exactly one client policy must exist (import must not drop it)");
        policies[0].GetProperty("name").GetString().Should().Be("fapi2-security-policy");
        policies[0].GetProperty("enabled").GetBoolean().Should().BeTrue();
        policies[0].GetProperty("profiles").EnumerateArray().Select(e => e.GetString())
            .Should().Contain("fapi2-security-profile");

        var executors = realm.GetProperty("clientProfiles").GetProperty("profiles")
            .EnumerateArray().SelectMany(p => p.GetProperty("executors").EnumerateArray()).ToList();

        // §II.1: PKCE S256 only - 'plain' is prohibited.
        var pkce = executors.Single(e => e.GetProperty("executor").GetString() == "pkce-enforcer");
        pkce.GetProperty("configuration").GetProperty("auto-configure").GetString().Should().Be("true");

        // §II.1: every issued token must be DPoP-bound.
        var dpop = executors.Single(e => e.GetProperty("executor").GetString() == "dpop-bind-enforcer");
        dpop.GetProperty("configuration").GetProperty("auto-configure").GetString().Should().Be("true");
        dpop.GetProperty("configuration").GetProperty("allow-only-refresh-token-binding").GetString()
            .Should().Be("false");

        // §IV.1: signing restricted to PS256/ES256 - RS*/HS*/'none' prohibited.
        var signing = executors.Single(e =>
            e.GetProperty("executor").GetString() == "secure-signature-algorithm");
        var allowed = signing.GetProperty("configuration").GetProperty("algorithm")
            .EnumerateArray().Select(e => e.GetString()).ToList();
        allowed.Should().Contain("PS256", "PS256 is the PRIMARY signing algorithm (§IV.1)");
        allowed.Should().Contain("ES256", "ES256 is permitted by §IV.1");
        allowed.Should().NotContain("RS256", "RS256 is PROHIBITED by §IV.1");
        allowed.Should().NotContain("HS256", "HS256 is PROHIBITED by §IV.1");
        signing.GetProperty("configuration").GetProperty("default-algorithm").GetString()
            .Should().Be("PS256", "PS256 must be the realm default");

        // §II.1: implicit flow and ROPC grants are prohibited outright.
        executors.Select(e => e.GetProperty("executor").GetString())
            .Should().Contain(new[] { "reject-implicit-grant", "reject-ropc-grant" },
                "implicit and ROPC must be rejected at the policy layer");

        // No configured client may have implicit or direct-access grants
        // enabled. Keycloak's own bootstrap clients (admin-cli, account,
        // security-admin-console, realm-management, broker) are exempt: they
        // are internal tooling, and the reject-* executors apply to them the
        // same as everything else at the token endpoint.
        var bootstrapClients = new[]
        {
            "admin-cli", "account", "account-console",
            "security-admin-console", "realm-management", "broker"
        };
        var clientsResponse = await _fixture.SendAdminAsync(HttpMethod.Get, "/clients?max=100", cancellationToken: TestContext.Current.CancellationToken);
        clientsResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        using var clientsDoc = JsonDocument.Parse(await clientsResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var clients = clientsDoc.RootElement.EnumerateArray()
            .Where(c => !bootstrapClients.Contains(c.GetProperty("clientId").GetString()))
            .ToList();
        clients.Should().NotBeEmpty();
        foreach (var client in clients)
        {
            client.GetProperty("implicitFlowEnabled").GetBoolean().Should().BeFalse(
                $"client '{client.GetProperty("clientId").GetString()}' implicit flow is PROHIBITED (§II.1)");
            client.GetProperty("directAccessGrantsEnabled").GetBoolean().Should().BeFalse(
                $"client '{client.GetProperty("clientId").GetString()}' ROPC grant is PROHIBITED (§II.1)");
        }

        // §IV.2: no ACTIVE RS256 key may exist in the realm.
        var keysResponse = await _fixture.SendAdminAsync(HttpMethod.Get, "/keys", cancellationToken: TestContext.Current.CancellationToken);
        keysResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        using var keysDoc = JsonDocument.Parse(await keysResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var active = keysDoc.RootElement.GetProperty("keys").EnumerateArray()
            .Where(k => k.TryGetProperty("status", out var s) && s.GetString() == "ACTIVE").ToList();
        active.Should().NotBeEmpty("at least one ACTIVE signing key must exist");
        active.Select(k => k.GetProperty("algorithm").GetString())
            .Should().NotContain("RS256", "no ACTIVE RS256 key may exist (§IV.2)");

        // Event pipeline: only real providers may be registered.
        realm.GetProperty("eventsListeners").EnumerateArray().Select(e => e.GetString())
            .Should().BeEquivalentTo(["jboss-logging"],
                "exported event listeners must resolve to real providers");
    }

    [Fact(DisplayName = "CONTRACT: required Sentinel scopes advertised")]
    public async Task DiscoveryDocument_Scopes_IncludeRequiredScopes()
    {
        var json = await FetchDiscoveryDocumentAsync();

        var scopes = json.GetProperty("scopes_supported")
            .EnumerateArray().Select(e => e.GetString()).ToList();

        scopes.Should().Contain("openid", "OIDC baseline scope");
        scopes.Should().Contain("profile", "profile scope for user info");
        scopes.Should().Contain("offline_access", "required for refresh tokens");
    }

    private async Task<JsonElement> FetchDiscoveryDocumentAsync()
    {
        var response = await _fixture.HttpClient.GetAsync(_fixture.DiscoveryUrl);
        response.StatusCode.Should().Be(HttpStatusCode.OK, "discovery endpoint must return 200");

        var content = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(content);
        return document.RootElement.Clone();
    }
}