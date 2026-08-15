using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.Tests.Integration.Federation;

/// <summary>
///     FAPI 2.0-compliant browser flow client for the E2E tests: PAR, PKCE S256,
///     DPoP-bound token exchange and protected-resource calls, all against a real
///     Keycloak instance.
///
///     Behavior verified live against Keycloak 26.6.4 (sentinel-dast realm):
///     - the client policy REQUIRES `nonce` in the pushed authorization request
///       (authorize rejects PAR without it: "Missing parameter: nonce");
///     - the token endpoint binds the issued token to the DPoP key declared via
///       `dpop_jkt` in PAR (a mismatched thumbprint yields 400);
///     - Keycloak issues NO DPoP-Nonce in this configuration; the nonce
///       challenge-response path is implemented for spec completeness and is a
///       no-op against this server.
/// </summary>
public sealed class Fapi2BrowserClient : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly Fapi2DpopProofBuilder _dpopBuilder;
    private readonly string _clientId;
    private readonly string _redirectUri;
    private readonly string _realmUrl;

    public Fapi2BrowserClient(
        HttpClient httpClient,
        string clientId,
        string redirectUri,
        string keycloakBaseUrl,
        string realm)
    {
        _httpClient = httpClient;
        _dpopBuilder = new Fapi2DpopProofBuilder();
        _clientId = clientId;
        _redirectUri = redirectUri;
        _realmUrl = $"{keycloakBaseUrl.TrimEnd('/')}/realms/{realm}";
    }

    public Fapi2DpopProofBuilder DpopBuilder => _dpopBuilder;

    public string ParEndpoint => $"{_realmUrl}/protocol/openid-connect/ext/par/request";

    public string TokenEndpoint => $"{_realmUrl}/protocol/openid-connect/token";

    public string AuthorizationEndpoint => $"{_realmUrl}/protocol/openid-connect/auth";

    /// <summary>RFC 7636: 96 bytes of CSPRNG entropy, base64url, S256 challenge.</summary>
    public static (string CodeVerifier, string CodeChallenge) GeneratePkceS256()
    {
        var codeVerifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(96));
        var codeChallenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));
        return (codeVerifier, codeChallenge);
    }

    public static string GenerateState() => Guid.NewGuid().ToString("N");

    public static string GenerateNonce() => Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));

    /// <summary>Pushed Authorization Request (RFC 9126).</summary>
    public async Task<ParResponse> SubmitParRequestAsync(
        string scope,
        string codeChallenge,
        string state,
        string nonce,
        string codeChallengeMethod = "S256",
        CancellationToken ct = default)
    {
        var parameters = new Dictionary<string, string>
        {
            ["client_id"] = _clientId,
            ["response_type"] = "code",
            ["redirect_uri"] = _redirectUri,
            ["scope"] = scope,
            ["state"] = state,
            ["nonce"] = nonce,
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = codeChallengeMethod,
            // Binds the authorization code to the DPoP key used at the token
            // endpoint; verified REQUIRED by the token endpoint on 26.6.4.
            ["dpop_jkt"] = _dpopBuilder.JwkThumbprint
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, ParEndpoint)
        {
            Content = new FormUrlEncodedContent(parameters)
        };

        using var response = await _httpClient.SendAsync(request, ct);
        var responseBody = await response.Content.ReadAsStringAsync(ct);

        if (!response.IsSuccessStatusCode)
        {
            throw new ParRequestException(
                $"PAR request failed with status {response.StatusCode}: {responseBody}",
                response.StatusCode,
                responseBody);
        }

        return JsonSerializer.Deserialize<ParResponse>(responseBody)
            ?? throw new InvalidOperationException("Failed to deserialize PAR response");
    }

    /// <summary>RFC 9126: request_uri goes to /authorize as a query parameter.</summary>
    public Uri BuildAuthorizationUrl(Uri requestUri)
        => new($"{AuthorizationEndpoint}?client_id={_clientId}&request_uri={Uri.EscapeDataString(requestUri.ToString())}");

    /// <summary>Exchanges an authorization code for a DPoP-bound token set.</summary>
    public async Task<TokenResponse> ExchangeCodeForTokensAsync(
        string code,
        string codeVerifier,
        string? dpopNonce = null,
        CancellationToken ct = default)
    {
        var parameters = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = _redirectUri,
            ["client_id"] = _clientId,
            ["code_verifier"] = codeVerifier
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(parameters)
        };
        request.Headers.Add("DPoP", _dpopBuilder.BuildTokenEndpointProof(TokenEndpoint, dpopNonce));

        using var response = await _httpClient.SendAsync(request, ct);
        var responseBody = await response.Content.ReadAsStringAsync(ct);

        // RFC 9449 nonce challenge: retry once with the server-issued nonce.
        // A no-op against Keycloak 26.6.4, which does not issue nonces here.
        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized
            && response.Headers.WwwAuthenticate.ToString().Contains("use_dpop_nonce", StringComparison.OrdinalIgnoreCase)
            && response.Headers.TryGetValues("DPoP-Nonce", out var nonces))
        {
            return await ExchangeCodeForTokensAsync(code, codeVerifier, nonces.First(), ct);
        }

        if (!response.IsSuccessStatusCode)
        {
            throw new TokenExchangeException(
                $"Token exchange failed with status {response.StatusCode}: {responseBody}",
                response.StatusCode,
                responseBody);
        }

        var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseBody)
            ?? throw new InvalidOperationException("Failed to deserialize token response");

        if (response.Headers.TryGetValues("DPoP-Nonce", out var responseNonces))
        {
            tokenResponse.DpopNonce = responseNonces.First();
        }

        return tokenResponse;
    }

    /// <summary>Protected-resource call with a DPoP-bound proof (ath claim).</summary>
    public async Task<HttpResponseMessage> CallProtectedResourceAsync(
        string resourceUrl,
        string accessToken,
        string? dpopNonce = null,
        string httpMethod = "GET",
        string? explicitJti = null,
        CancellationToken ct = default)
    {
        var dpopProof = _dpopBuilder.BuildResourceRequestProof(
            httpMethod, resourceUrl, accessToken, dpopNonce, explicitJti);

        using var request = new HttpRequestMessage(new HttpMethod(httpMethod), resourceUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
        request.Headers.Add("DPoP", dpopProof);

        var response = await _httpClient.SendAsync(request, ct);

        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized
            && (response.Headers.WwwAuthenticate.ToString().Contains("use_dpop_nonce", StringComparison.OrdinalIgnoreCase))
            && response.Headers.TryGetValues("DPoP-Nonce", out var nonces))
        {
            response.Dispose();
            return await CallProtectedResourceAsync(resourceUrl, accessToken, nonces.First(), httpMethod, explicitJti, ct);
        }

        return response;
    }

    public void Dispose() => _dpopBuilder.Dispose();
}

public sealed record ParResponse(
    [property: JsonPropertyName("request_uri")] Uri RequestUri,
    [property: JsonPropertyName("expires_in")] int ExpiresIn);

public sealed record TokenResponse(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("token_type")] string TokenType,
    [property: JsonPropertyName("expires_in")] int ExpiresIn,
    [property: JsonPropertyName("refresh_token")] string? RefreshToken,
    [property: JsonPropertyName("id_token")] string? IdToken,
    [property: JsonPropertyName("scope")] string? Scope)
{
    public string? DpopNonce { get; set; }
}

public sealed class ParRequestException : Exception
{
    public ParRequestException(string message, System.Net.HttpStatusCode statusCode, string responseBody)
        : base(message)
    {
        StatusCode = statusCode;
        ResponseBody = responseBody;
    }

    public System.Net.HttpStatusCode StatusCode { get; }

    public string ResponseBody { get; }
}

public sealed class TokenExchangeException : Exception
{
    public TokenExchangeException(string message, System.Net.HttpStatusCode statusCode, string responseBody)
        : base(message)
    {
        StatusCode = statusCode;
        ResponseBody = responseBody;
    }

    public System.Net.HttpStatusCode StatusCode { get; }

    public string ResponseBody { get; }
}

/// <summary>RFC 7636-style base64url for PKCE material.</summary>
internal static class Base64UrlEncoder
{
    public static string Encode(byte[] value)
        => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
