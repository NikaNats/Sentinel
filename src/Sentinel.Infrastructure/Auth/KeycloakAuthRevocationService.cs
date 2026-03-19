// Sentinel Security API - FAPI 2.0 Compliant
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Infrastructure.Telemetry;

namespace Sentinel.Infrastructure.Auth;

public sealed class KeycloakAuthRevocationService(
    HttpClient httpClient,
    IHttpClientFactory httpClientFactory,
    KeycloakAdminTokenProvider adminTokenProvider,
    IConfiguration configuration,
    ISecurityEventEmitter securityEventEmitter,
    ILogger<KeycloakAuthRevocationService> logger) : IAuthRevocationService
{
    public async Task<IReadOnlyCollection<UserSessionInfo>> GetActiveSessionsAsync(string subjectId, CancellationToken ct)
    {
        var adminHttpClient = httpClientFactory.CreateClient("keycloak-admin");
        var adminContext = await TryResolveAdminContextAsync(ct);
        if (adminContext is null)
        {
            return [];
        }

        var sessionsEndpoint = new Uri(adminContext.AdminRealmEndpoint, $"users/{Uri.EscapeDataString(subjectId)}/sessions");
        using var request = new HttpRequestMessage(HttpMethod.Get, sessionsEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminContext.AdminToken);

        try
        {
            using var response = await adminHttpClient.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                return [];
            }

            var sessions = await response.Content.ReadFromJsonAsync<List<KeycloakSessionResponse>>(cancellationToken: ct) ?? [];
            return sessions
                .Where(x => !string.IsNullOrWhiteSpace(x.Id))
                .Select(x => new UserSessionInfo(
                    x.Id!,
                    x.IpAddress,
                    FromUnixMilliseconds(x.Start),
                    FromUnixMilliseconds(x.LastAccess),
                    x.Clients?.Keys.ToArray() ?? []))
                .ToArray();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to list active sessions for sub {Sub}.", subjectId);
            return [];
        }
    }

    public async Task<bool> RevokeSessionAsync(string subjectId, string sessionId, CancellationToken ct)
    {
        _ = subjectId;
        var adminHttpClient = httpClientFactory.CreateClient("keycloak-admin");
        var adminContext = await TryResolveAdminContextAsync(ct);
        if (adminContext is null)
        {
            return false;
        }

        var endpoint = new Uri(adminContext.AdminRealmEndpoint, $"sessions/{Uri.EscapeDataString(sessionId)}");
        using var request = new HttpRequestMessage(HttpMethod.Delete, endpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminContext.AdminToken);

        try
        {
            using var response = await adminHttpClient.SendAsync(request, ct);
            return response.IsSuccessStatusCode || response.StatusCode == System.Net.HttpStatusCode.NoContent;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to revoke session {SessionId}.", sessionId);
            return false;
        }
    }

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
        if (string.IsNullOrWhiteSpace(authority)
            || !KeycloakAuthorityEndpoints.TryBuild(authority, out _, out var adminRealmEndpoint))
        {
            logger.LogWarning("Global logout skipped because Keycloak authority configuration is missing or invalid.");
            return false;
        }

        var adminAccessToken = await adminTokenProvider.GetAccessTokenAsync(ct);
        if (string.IsNullOrWhiteSpace(adminAccessToken))
        {
            logger.LogWarning("Global logout skipped because Keycloak admin token could not be acquired.");
            return false;
        }

        var adminLogoutEndpoint = new Uri(adminRealmEndpoint, $"users/{Uri.EscapeDataString(subjectId)}/logout");

        using var request = new HttpRequestMessage(HttpMethod.Post, adminLogoutEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminAccessToken);

        try
        {
            var adminHttpClient = httpClientFactory.CreateClient("keycloak-admin");
            using var response = await adminHttpClient.SendAsync(request, ct);
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

    public async Task<bool> DeleteAccountAsync(string subjectId, CancellationToken ct)
    {
        var authority = configuration["Keycloak:Authority"]?.TrimEnd('/');
        if (string.IsNullOrWhiteSpace(authority)
            || !KeycloakAuthorityEndpoints.TryBuild(authority, out _, out var adminRealmEndpoint))
        {
            logger.LogWarning("Account deletion skipped because Keycloak authority configuration is missing or invalid.");
            return false;
        }

        var adminAccessToken = await adminTokenProvider.GetAccessTokenAsync(ct);
        if (string.IsNullOrWhiteSpace(adminAccessToken))
        {
            logger.LogWarning("Account deletion skipped because Keycloak admin token could not be acquired.");
            return false;
        }

        var deleteEndpoint = new Uri(adminRealmEndpoint, $"users/{Uri.EscapeDataString(subjectId)}");
        using var request = new HttpRequestMessage(HttpMethod.Delete, deleteEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminAccessToken);

        try
        {
            var adminHttpClient = httpClientFactory.CreateClient("keycloak-admin");
            using var response = await adminHttpClient.SendAsync(request, ct);
            if (response.IsSuccessStatusCode)
            {
                logger.LogInformation("User {Sub} deleted from Keycloak.", subjectId);
                return true;
            }

            logger.LogWarning("Keycloak returned status {StatusCode} during account deletion for sub {Sub}.", (int)response.StatusCode, subjectId);
            return false;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to delete account for sub {Sub}.", subjectId);
            return false;
        }
    }

    private async Task<AdminContext?> TryResolveAdminContextAsync(CancellationToken ct)
    {
        var authority = configuration["Keycloak:Authority"]?.TrimEnd('/');
        if (string.IsNullOrWhiteSpace(authority)
            || !KeycloakAuthorityEndpoints.TryBuild(authority, out _, out var adminRealmEndpoint))
        {
            return null;
        }

        var adminToken = await adminTokenProvider.GetAccessTokenAsync(ct);
        if (string.IsNullOrWhiteSpace(adminToken))
        {
            return null;
        }

        return new AdminContext(adminRealmEndpoint, adminToken);
    }

    private static DateTimeOffset? FromUnixMilliseconds(long? unixMilliseconds)
    {
        if (unixMilliseconds is null || unixMilliseconds <= 0)
        {
            return null;
        }

        return DateTimeOffset.FromUnixTimeMilliseconds(unixMilliseconds.Value);
    }

    private sealed class KeycloakSessionResponse
    {
        public string? Id { get; set; }
        public string? IpAddress { get; set; }
        public long? Start { get; set; }
        public long? LastAccess { get; set; }
        public Dictionary<string, object>? Clients { get; set; }
    }

    private sealed record AdminContext(Uri AdminRealmEndpoint, string AdminToken);
}
