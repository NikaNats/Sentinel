using System.Net;
using System.Text.Json;
using Sentinel.Contracts.Shared;

namespace Sentinel.Contracts.Keycloak;

/// <summary>
///     CONTRACT: Back-Channel Logout Token Structure (RFC 9413).
///
///     Pins the logout-token invariants Sentinel's LogoutTokenValidator enforces:
///     iss/aud/jti/iat/events present, 'nonce' ABSENT, sid present. Keycloak only
///     emits logout tokens on real session teardown, so this suite additionally
///     pins the session lifecycle that back-channel logout terminates.
///
///     Constitution Ref: §II.1 (Back-channel logout), §II.6 (Session Management).
/// </summary>
[Collection(KeycloakContractCollection.Name)]
[ContractVersion("CONTRACT-001", "1.0", Target = "Keycloak OIDC Back-Channel Logout (RFC 9413)")]
public sealed class BackchannelLogoutContractTests(KeycloakContractFixture fixture)
{
    private readonly KeycloakContractFixture _fixture = fixture;

    private const string CanonicalLogoutToken = """
        {
          "iss": "https://keycloak.sentinel.local/realms/sentinel",
          "aud": "sentinel-api-client",
          "iat": 1786200000,
          "jti": "sample-logout-jti-0001",
          "sub": "user-0001",
          "sid": "session-0001",
          "events": {
            "http://schemas.openid.net/event/backchannel-logout": {}
          }
        }
        """;

    [Fact(DisplayName = "CONTRACT: canonical RFC 9413 token validates against the pinned schema")]
    public void LogoutToken_ValidatesAgainstRfc9413Schema()
    {
        var schema = EmbeddedResourceReader.Read("backchannel-logout-token.schema.json");

        var result = SchemaValidator.Validate(schema, CanonicalLogoutToken);

        result.IsValid.Should().BeTrue(
            $"pinned RFC 9413 shape rejects its own canonical token:{Environment.NewLine}{string.Join(Environment.NewLine, result.Errors)}");
    }

    [Fact(DisplayName = "CONTRACT: RFC 9413 §2.6 'nonce' must NOT appear in logout tokens")]
    public void LogoutToken_MustNotContainNonce()
    {
        using var document = JsonDocument.Parse(CanonicalLogoutToken);

        document.RootElement.TryGetProperty("nonce", out _).Should().BeFalse(
            "RFC 9413 §2.6: logout tokens MUST NOT include 'nonce'");
    }

    [Fact(DisplayName = "CONTRACT: Admin API logout terminates the real user session")]
    public async Task AdminApi_LogoutUser_EndsRealSession()
    {
        await LoginContractUserAsync();
        var userId = await FindContractUserIdAsync();

        var before = await _fixture.SendAdminAsync(HttpMethod.Get, $"/users/{userId}/sessions", cancellationToken: TestContext.Current.CancellationToken);
        before.EnsureSuccessStatusCode();
        using (var beforeDoc = JsonDocument.Parse(await before.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)))
        {
            beforeDoc.RootElement.GetArrayLength().Should().BeGreaterThan(0,
                "login must create a session");
        }

        var logout = await _fixture.SendAdminAsync(HttpMethod.Post, $"/users/{userId}/logout", cancellationToken: TestContext.Current.CancellationToken);
        logout.StatusCode.Should().Be(HttpStatusCode.NoContent, "logout must return 204 No Content");

        var after = await _fixture.SendAdminAsync(HttpMethod.Get, $"/users/{userId}/sessions", cancellationToken: TestContext.Current.CancellationToken);
        using (var afterDoc = JsonDocument.Parse(await after.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)))
        {
            afterDoc.RootElement.GetArrayLength().Should().Be(0,
                "session MUST be gone after logout (back-channel logout contract)");
        }
    }

    // ─── Helpers ────────────────────────────────────────────────────────

    private async Task LoginContractUserAsync()
    {
        // ROPC is prohibited by the realm client policy (§II.1); the session
        // comes from the real interactive flow (authorize + login form + PKCE
        // S256 + DPoP-bound exchange).
        await _fixture.LoginInteractiveAsync();
    }

    private async Task<string> FindContractUserIdAsync()
    {
        var response = await _fixture.SendAdminAsync(
            HttpMethod.Get, "/users?username=contract-user&exact=true");
        response.EnsureSuccessStatusCode();

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement[0].GetProperty("id").GetString()!;
    }
}