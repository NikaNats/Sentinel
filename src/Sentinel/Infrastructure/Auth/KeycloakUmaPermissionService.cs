using Sentinel.Application.Auth.Interfaces;
using Sentinel.Infrastructure.Telemetry;
using System.Diagnostics;
using System.Net.Http.Headers;

namespace Sentinel.Infrastructure.Auth;

public sealed class KeycloakUmaPermissionService(
    HttpClient httpClient,
    IConfiguration configuration,
    ILogger<KeycloakUmaPermissionService> logger) : IUmaPermissionService
{
    public async Task<bool> HasAccessAsync(string accessToken, string resourceId, string scope, CancellationToken ct)
    {
        using var activity = AuthTelemetry.Source.StartActivity("uma.permission.check", ActivityKind.Client);
        activity?.SetTag("uma.resource", resourceId);
        activity?.SetTag("uma.scope", scope);

        var authority = configuration["Keycloak:Authority"]?.TrimEnd('/');
        var audience = configuration["Keycloak:Audience"];

        if (string.IsNullOrWhiteSpace(authority) || string.IsNullOrWhiteSpace(audience))
        {
            logger.LogError("Keycloak UMA configuration is missing required Authority or Audience.");
            activity?.SetTag("uma.decision", "deny");
            return false;
        }

        var tokenEndpoint = $"{authority}/protocol/openid-connect/token";

        var requestBody = new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket"),
            new KeyValuePair<string, string>("audience", audience),
            new KeyValuePair<string, string>("permission", $"{resourceId}#{scope}"),
            new KeyValuePair<string, string>("response_mode", "decision")
        ]);

        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint) { Content = requestBody };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        try
        {
            using var response = await httpClient.SendAsync(request, ct);
            if (response.IsSuccessStatusCode)
            {
                activity?.SetTag("uma.decision", "permit");
                return true;
            }

            activity?.SetTag("uma.decision", "deny");
            logger.LogWarning("UMA access denied for resource {Resource} and scope {Scope}. status={StatusCode}", resourceId, scope, (int)response.StatusCode);
            return false;
        }
        catch (Exception ex)
        {
            activity?.SetTag("error", true);
            activity?.SetTag("uma.decision", "deny");
            logger.LogError(ex, "Failed to query Keycloak UMA endpoint.");
            return false;
        }
    }
}
