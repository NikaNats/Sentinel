using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Sentinel.Application.Auth.Interfaces;

namespace Sentinel.Keycloak;

public sealed class KeycloakTokenRefreshService(
    HttpClient httpClient,
    IOptions<KeycloakOptions> options,
    ILogger<KeycloakTokenRefreshService> logger) : Sentinel.Application.Auth.Interfaces.ITokenRefreshService
{
    private readonly KeycloakOptions keycloakOptions = options.Value;

    public async Task<TokenRefreshResult> RefreshTokenAsync(string refreshToken, string dpopProof, string clientIpHash,
        CancellationToken ct)
    {
        var authority = keycloakOptions.Authority.TrimEnd('/');
        var clientId = keycloakOptions.Audience;

        if (string.IsNullOrWhiteSpace(authority) || string.IsNullOrWhiteSpace(clientId))
        {
            logger.LogError("Token refresh configuration is missing Keycloak authority or audience.");
            return new TokenRefreshResult(false, null, null, false);
        }

        var tokenEndpoint = $"{authority}/protocol/openid-connect/token";

        var requestBody = new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("grant_type", "refresh_token"),
            new KeyValuePair<string, string>("client_id", clientId),
            new KeyValuePair<string, string>("refresh_token", refreshToken)
        ]);

        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint) { Content = requestBody };
        if (!string.IsNullOrWhiteSpace(dpopProof))
        {
            request.Headers.Add("DPoP", dpopProof);
        }

        try
        {
            using var response = await httpClient.SendAsync(request, ct);
            var responseContent = await response.Content.ReadAsStringAsync(ct);

            if (response.IsSuccessStatusCode)
            {
                using var json = JsonDocument.Parse(responseContent);
                var accessToken = json.RootElement.TryGetProperty("access_token", out var at)
                    ? at.GetString()
                    : null;
                var rotatedRefreshToken = json.RootElement.TryGetProperty("refresh_token", out var rt)
                    ? rt.GetString()
                    : null;

                return new TokenRefreshResult(true, accessToken, rotatedRefreshToken, false);
            }

            if (IsRefreshReuseDetected(response.StatusCode, responseContent))
            {
                logger.LogCritical("CRITICAL: Refresh token reuse or invalid grant detected. Potential token theft.");
                return new TokenRefreshResult(false, null, null, true);
            }

            logger.LogWarning("Refresh token request failed with status code {StatusCode}.", (int)response.StatusCode);
            return new TokenRefreshResult(false, null, null, false);
        }
#pragma warning disable CA1031 // Intentional catch-all: refresh failures should fail closed and return unauthorized state.
        catch (Exception ex)
        {
            logger.LogError(ex, "HTTP exception during refresh token exchange.");
            return new TokenRefreshResult(false, null, null, false);
        }
#pragma warning restore CA1031
    }

    private static bool IsRefreshReuseDetected(HttpStatusCode statusCode, string responseContent)
    {
        if (statusCode != HttpStatusCode.BadRequest)
        {
            return false;
        }

        try
        {
            using var json = JsonDocument.Parse(responseContent);
            if (json.RootElement.TryGetProperty("error", out var errorProp))
            {
                return string.Equals(errorProp.GetString(), "invalid_grant", StringComparison.OrdinalIgnoreCase);
            }
        }
        catch (JsonException)
        {
            // Fallback to string matching if Keycloak returns non-JSON content.
        }

        return responseContent.Contains("invalid_grant", StringComparison.OrdinalIgnoreCase);
    }
}
