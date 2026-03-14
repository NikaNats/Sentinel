using Sentinel.Application.Auth.Interfaces;
using Sentinel.Infrastructure.Telemetry;

namespace Sentinel.Infrastructure.Auth;

public sealed class KeycloakAuthRevocationService(
    HttpClient httpClient,
    IConfiguration configuration,
    ISecurityEventEmitter securityEventEmitter,
    ILogger<KeycloakAuthRevocationService> logger) : IAuthRevocationService
{
    public async Task<bool> RevokeCurrentSessionAsync(string refreshToken, CancellationToken ct)
    {
        var authority = configuration["Keycloak:Authority"]?.TrimEnd('/');
        var clientId = configuration["Keycloak:Audience"];

        if (string.IsNullOrWhiteSpace(authority) || string.IsNullOrWhiteSpace(clientId))
        {
            logger.LogWarning("Revocation skipped because Keycloak authority or audience configuration is missing.");
            return false;
        }

        var revokeEndpoint = $"{authority}/protocol/openid-connect/revoke";
        var requestBody = new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("client_id", clientId),
            new KeyValuePair<string, string>("token", refreshToken),
            new KeyValuePair<string, string>("token_type_hint", "refresh_token")
        ]);

        using var request = new HttpRequestMessage(HttpMethod.Post, revokeEndpoint) { Content = requestBody };

        try
        {
            using var response = await httpClient.SendAsync(request, ct);
            if (response.IsSuccessStatusCode)
            {
                logger.LogInformation("Current session revoked in Keycloak.");
                return true;
            }

            logger.LogWarning("Keycloak returned status {StatusCode} during current session revocation.", (int)response.StatusCode);
            return false;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to reach Keycloak for current session revocation.");
            return false;
        }
    }

    public async Task<bool> RevokeAllSessionsAsync(string subjectId, CancellationToken ct)
    {
        var authority = configuration["Keycloak:Authority"]?.TrimEnd('/');
        if (string.IsNullOrWhiteSpace(authority))
        {
            logger.LogWarning("Global logout skipped because Keycloak authority configuration is missing.");
            return false;
        }

        var adminLogoutEndpoint = authority.Replace("/realms/", "/admin/realms/", StringComparison.OrdinalIgnoreCase)
            + $"/users/{subjectId}/logout";

        using var request = new HttpRequestMessage(HttpMethod.Post, adminLogoutEndpoint);

        try
        {
            using var response = await httpClient.SendAsync(request, ct);
            if (response.IsSuccessStatusCode)
            {
                securityEventEmitter.EmitAuthFailure("global_logout_triggered", subjectId, "internal");
                logger.LogInformation("Global logout executed for sub {Sub}.", subjectId);
                return true;
            }

            logger.LogWarning("Keycloak returned status {StatusCode} during global logout for sub {Sub}.", (int)response.StatusCode, subjectId);
            return false;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to execute global logout for sub {Sub}.", subjectId);
            return false;
        }
    }
}
