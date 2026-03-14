using Sentinel.Application.Auth.Interfaces;
using Sentinel.Infrastructure.Telemetry;
using System.Net;
using System.Text.Json;

namespace Sentinel.Infrastructure.Auth;

public sealed class KeycloakTokenRefreshService(
    HttpClient httpClient,
    IConfiguration configuration,
    ISecurityEventEmitter securityEventEmitter,
    ILogger<KeycloakTokenRefreshService> logger) : ITokenRefreshService
{
    public async Task<TokenRefreshResult> RefreshTokenAsync(string refreshToken, string dpopProof, CancellationToken ct)
    {
        var authority = configuration["Keycloak:Authority"]?.TrimEnd('/');
        var clientId = configuration["Keycloak:Audience"];

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
                securityEventEmitter.EmitAuthFailure("refresh_token_reuse_detected", null, "unknown_ip");
                return new TokenRefreshResult(false, null, null, true);
            }

            logger.LogWarning("Refresh token request failed with status code {StatusCode}.", (int)response.StatusCode);
            return new TokenRefreshResult(false, null, null, false);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "HTTP exception during refresh token exchange.");
            return new TokenRefreshResult(false, null, null, false);
        }
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
