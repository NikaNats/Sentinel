using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Sentinel.Contracts.Shared;

namespace Sentinel.Contracts.Keycloak;

/// <summary>
///     CONTRACT: Token Endpoint Response Shape.
///
///     Issues REAL token requests against the live Keycloak container and pins
///     the wire format the Sentinel token pipeline consumes.
///
///     Constitution Ref: §II.4 (Token Security), §IV.1 (Signing Algorithms).
/// </summary>
[Collection(KeycloakContractCollection.Name)]
[ContractVersion("CONTRACT-001", "1.0", Target = "Keycloak 26.6.4")]
public sealed class TokenResponseContractTests(KeycloakContractFixture fixture)
{
    private readonly KeycloakContractFixture _fixture = fixture;

    [Fact(DisplayName = "CONTRACT: client credentials returns complete, schema-valid token response")]
    public async Task TokenEndpoint_ClientCredentials_ReturnsCompleteTokenResponse()
    {
        var response = await PostWithDpopAsync(Credentials());

        response.StatusCode.Should().Be(HttpStatusCode.OK, "token endpoint must accept valid client_credentials");
        var content = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        var schemaResult = SchemaValidator.Validate(
            EmbeddedResourceReader.Read("token-response.schema.json"), content);
        schemaResult.IsValid.Should().BeTrue(
            $"token response drifted from the pinned schema:{Environment.NewLine}{string.Join(Environment.NewLine, schemaResult.Errors)}");

        using var document = JsonDocument.Parse(content);
        var root = document.RootElement;

        var tokenType = root.GetProperty("token_type").GetString();
        tokenType.Should().Be("DPoP", "DPoP-bound tokens are identified as token_type 'DPoP' (§II.1)");

        var lifetime = root.GetProperty("expires_in").GetInt32();
        lifetime.Should().BeLessThanOrEqualTo(300, "access token lifetime ≤ 300s (Constitution §II.4)");
        lifetime.Should().BeGreaterThan(0);

        var accessTokenValue = root.GetProperty("access_token").GetString()!;
        var handler = new JsonWebTokenHandler();
        handler.CanReadToken(accessTokenValue).Should().BeTrue("access_token must be a readable JWT");

        var jwt = handler.ReadJsonWebToken(accessTokenValue);
        jwt.Alg.Should().Be("PS256", "access token MUST be PS256-signed (§IV.1 primary algorithm)");
        jwt.Subject.Should().NotBeNullOrWhiteSpace("access token MUST contain 'sub'");
        jwt.Issuer.Should().Be(_fixture.RealmUrl.ToString(), "access token 'iss' must match realm URL");
        jwt.Audiences.Should().Contain("sentinel-api", "access token MUST carry the sentinel-api audience");
        jwt.Id.Should().NotBeNullOrWhiteSpace("access token MUST contain 'jti' (§II.4)");
        jwt.ValidTo.Should().BeAfter(DateTime.UtcNow, "token must not be expired at issuance");
        jwt.EncodedPayload.Should().NotBeNullOrWhiteSpace();
    }

    [Fact(DisplayName = "CONTRACT: invalid client credentials returns RFC 6749 error format")]
    public async Task TokenEndpoint_InvalidCredentials_ReturnsRfc6749ErrorFormat()
    {
        using var invalidBody = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = "nonexistent-client",
                ["client_secret"] = "wrong-secret"
            });
        var response = await _fixture.HttpClient.PostAsync(
            _fixture.TokenEndpoint, invalidBody, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized, "invalid client MUST return 401");

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var root = document.RootElement;

        var error = root.GetProperty("error").GetString();
        error.Should().Be("invalid_client", "RFC 6749 §5.2 error code for unknown clients");

        root.TryGetProperty("error_description", out _).Should().BeTrue(
            "RFC 6749 §5.2 error_description SHOULD be present");
    }

    [Fact(DisplayName = "CONTRACT: refresh grant rotates the refresh token (if issued)")]
    public async Task TokenEndpoint_RefreshGrant_ReturnsRotatedRefreshToken()
    {
        var initialResponse = await PostWithDpopAsync(Credentials());
        var initialJson = await initialResponse.Content.ReadFromJsonAsync(
            KeycloakContractJsonContext.Default.TokenResponseContract, TestContext.Current.CancellationToken);

        if (initialJson?.RefreshToken is null)
        {
            await WithTokenDocument(initialResponse, static element =>
            {
                element.TryGetProperty("refresh_token", out _).Should().BeFalse(
                    "when refresh tokens are not issued, 'refresh_token' must be ABSENT, never null");
            });
            return;
        }

        var refreshResponse = await PostWithDpopAsync(
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = initialJson.RefreshToken,
                ["client_id"] = KeycloakContractFixture.ContractClientId,
                ["client_secret"] = KeycloakContractFixture.ContractClientSecret
            }));

        refreshResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var refreshJson = await refreshResponse.Content.ReadFromJsonAsync(
            KeycloakContractJsonContext.Default.TokenResponseContract, TestContext.Current.CancellationToken);

        refreshJson!.RefreshToken.Should().NotBe(initialJson.RefreshToken,
            "refresh token MUST rotate per use (§II.4)");
        refreshJson.AccessToken.Should().NotBeNullOrWhiteSpace("refresh grant must return a new access token");
    }

    private async Task<HttpResponseMessage> PostWithDpopAsync(FormUrlEncodedContent content)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, _fixture.TokenEndpoint)
        {
            Content = content
        };
        request.Headers.Add("DPoP", DpopProofBuilder.CreateProof(_fixture.TokenEndpoint));
        return await _fixture.HttpClient.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private static FormUrlEncodedContent Credentials() => new(new Dictionary<string, string>
    {
        ["grant_type"] = "client_credentials",
        ["client_id"] = KeycloakContractFixture.ContractClientId,
        ["client_secret"] = KeycloakContractFixture.ContractClientSecret,
        ["scope"] = "openid profile"
    });

    private static async Task WithTokenDocument(HttpResponseMessage response, Action<JsonElement> assertion)
    {
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        assertion(document.RootElement);
    }
}