using System.Net;
using System.Text.Json;
using Sentinel.Contracts.Shared;

namespace Sentinel.Contracts.Keycloak;

/// <summary>
///     CONTRACT: JWKS (JSON Web Key Set) Structure.
///
///     Pins the RFC 7517 key shape Microsoft.IdentityModel's key resolution
///     pipeline parses. Includes private-material and algorithm guards.
///
///     Constitution Ref: §IV.1 (Signing Algorithms), §IV.2 (Key Management).
/// </summary>
[Collection(KeycloakContractCollection.Name)]
[ContractVersion("CONTRACT-001", "1.0", Target = "Keycloak 26.6.4")]
public sealed class JwksContractTests(KeycloakContractFixture fixture)
{
    private readonly KeycloakContractFixture _fixture = fixture;

    private static readonly string[] PermittedAlgorithms =
        ["PS256", "PS384", "PS512", "ES256", "ES384", "ES512"];

    private static readonly string[] PrivateMaterialFields = ["d", "p", "q", "dp", "dq", "qi"];

    [Fact(DisplayName = "CONTRACT: JWKS returns a non-empty key set")]
    public async Task JwksEndpoint_ReturnsValidKeySet()
    {
        var response = await _fixture.HttpClient.GetAsync(_fixture.JwksUri, TestContext.Current.CancellationToken);
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var keys = await ReadKeysAsync(response);
        keys.GetArrayLength().Should().BeGreaterThan(0, "JWKS must contain at least one signing key");
    }

    [Theory(DisplayName = "CONTRACT: each JWKS key carries the required JWK fields")]
    [InlineData("kty")]
    [InlineData("kid")]
    [InlineData("use")]
    [InlineData("alg")]
    public async Task JwksEndpoint_EachKey_HasRequiredField(string field)
    {
        var response = await _fixture.HttpClient.GetAsync(_fixture.JwksUri, TestContext.Current.CancellationToken);
        var keys = await ReadKeysAsync(response);

        foreach (var key in keys.EnumerateArray())
        {
            key.TryGetProperty(field, out var value).Should().BeTrue(
                $"every JWKS key MUST contain '{field}' (breaks Microsoft.IdentityModel key resolution)");
            value.ValueKind.Should().Be(JsonValueKind.String);
            value.GetString().Should().NotBeNullOrWhiteSpace();
        }
    }

    [Fact(DisplayName = "CONTRACT: JWKS validates against the pinned schema (signing keys)")]
    public async Task JwksEndpoint_ValidatesAgainstPinnedSchema()
    {
        var response = await _fixture.HttpClient.GetAsync(_fixture.JwksUri, TestContext.Current.CancellationToken);
        var keys = await ReadKeysAsync(response);

        var schema = EmbeddedResourceReader.Read("jwks-key.schema.json");

        foreach (var key in keys.EnumerateArray().Where(SignsTokens))
        {
            var result = SchemaValidator.Validate(schema, key.GetRawText());
            result.IsValid.Should().BeTrue(
                $"JWKS key drifted from the pinned schema:{Environment.NewLine}{string.Join(Environment.NewLine, result.Errors)}");
        }
    }

    [Fact(DisplayName = "CONTRACT: signing keys are Constitution-permitted; PS256 is the primary")]
    public async Task JwksEndpoint_Keys_UsePermittedAlgorithms()
    {
        var response = await _fixture.HttpClient.GetAsync(_fixture.JwksUri, TestContext.Current.CancellationToken);
        var keys = await ReadKeysAsync(response);

        var signingKeys = keys.EnumerateArray().Where(SignsTokens).ToList();

        signingKeys.Should().NotBeEmpty(
            "JWKS must publish at least one signing key (encryption keys alone would break token validation)");

        foreach (var key in signingKeys)
        {
            if (key.TryGetProperty("alg", out var algValue))
            {
                algValue.GetString().Should().BeOneOf(
                    PermittedAlgorithms,
                    $"algorithm must be in the §IV.1 permitted list; RS256/HS256/'none' are PROHIBITED");
            }
        }

        signingKeys.Select(k => k.GetProperty("alg").GetString())
            .Should().Contain("PS256", "PS256 is the PRIMARY signing algorithm (§IV.1)");
    }

    [Fact(DisplayName = "CONTRACT: JWKS never exposes private key material")]
    public async Task JwksEndpoint_Keys_DoNotContainPrivateMaterial()
    {
        var response = await _fixture.HttpClient.GetAsync(_fixture.JwksUri, TestContext.Current.CancellationToken);
        var keys = await ReadKeysAsync(response);

        foreach (var key in keys.EnumerateArray())
        {
            foreach (var privateField in PrivateMaterialFields)
            {
                key.TryGetProperty(privateField, out _).Should().BeFalse(
                    $"JWKS MUST NOT expose private parameter '{privateField}' (CRITICAL)");
            }
        }
    }

    [Fact(DisplayName = "CONTRACT: RSA JWKS keys carry modulus and exponent")]
    public async Task JwksEndpoint_RsaKeys_HaveRequiredParameters()
    {
        var response = await _fixture.HttpClient.GetAsync(_fixture.JwksUri, TestContext.Current.CancellationToken);
        var keys = await ReadKeysAsync(response);

        foreach (var key in keys.EnumerateArray())
        {
            if (key.TryGetProperty("kty", out var kty) && kty.GetString() == "RSA")
            {
                key.TryGetProperty("n", out _).Should().BeTrue("RSA key MUST contain modulus 'n'");
                key.TryGetProperty("e", out _).Should().BeTrue("RSA key MUST contain exponent 'e'");
            }
        }
    }

    /// <summary>
    ///     Keycloak 26.6.4 always publishes an encryption key (RSA-OAEP,
    ///     <c>use=enc</c>) in JWKS. It is not signing material, so algorithm and
    ///     schema pins apply to <c>use=sig</c> keys only (Constitution §IV.1
    ///     governs the algorithms used to SIGN tokens).
    /// </summary>
    private static bool SignsTokens(JsonElement key) =>
        key.TryGetProperty("use", out var use) && use.GetString() == "sig";

    private static async Task<JsonElement> ReadKeysAsync(HttpResponseMessage response)
    {
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.GetProperty("keys").Clone();
    }
}