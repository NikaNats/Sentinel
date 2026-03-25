// Sentinel Security API - FAPI 2.0 Compliant

using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Sentinel.Keycloak;

public sealed class KeycloakAdminTokenProvider(
    IHttpClientFactory httpClientFactory,
    IOptions<KeycloakOptions> options,
    ILogger<KeycloakAdminTokenProvider> logger,
    TimeProvider? timeProvider = null) : IDisposable
{
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private readonly KeycloakOptions keycloakOptions = options.Value;
    private readonly SemaphoreSlim tokenLock = new(1, 1);

    private string? cachedAccessToken;
    private DateTimeOffset cachedAccessTokenExpiresAt;

    public void Dispose()
    {
        tokenLock.Dispose();
    }

    public async Task<string?> GetAccessTokenAsync(CancellationToken ct)
    {
        if (HasUsableCachedToken())
        {
            return cachedAccessToken;
        }

        await tokenLock.WaitAsync(ct);
        try
        {
            if (HasUsableCachedToken())
            {
                return cachedAccessToken;
            }

            var authority = keycloakOptions.Authority.TrimEnd('/');
            var adminClientId = keycloakOptions.Admin.ClientId;
            var adminClientSecret = keycloakOptions.Admin.ClientSecret;
            var adminScope = keycloakOptions.Admin.Scope;

            if (string.IsNullOrWhiteSpace(authority)
                || string.IsNullOrWhiteSpace(adminClientId)
                || string.IsNullOrWhiteSpace(adminClientSecret)
                || !KeycloakAuthorityEndpoints.TryBuild(authority, out var tokenEndpoint, out _))
            {
                logger.LogWarning(
                    "Cannot acquire Keycloak admin token because authority/admin credentials are missing or invalid.");
                return null;
            }

            var requestPairs = new List<KeyValuePair<string, string>>
            {
                new("grant_type", "client_credentials"),
                new("client_id", adminClientId),
                new("client_secret", adminClientSecret)
            };

            if (!string.IsNullOrWhiteSpace(adminScope))
            {
                requestPairs.Add(new KeyValuePair<string, string>("scope", adminScope));
            }

            using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
            {
                Content = new FormUrlEncodedContent(requestPairs)
            };

            var adminHttpClient = httpClientFactory.CreateClient("keycloak-admin");
            using var response = await adminHttpClient.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("Failed to acquire Keycloak admin token. Status code: {StatusCode}",
                    (int)response.StatusCode);
                return null;
            }

            await using var responseStream = await response.Content.ReadAsStreamAsync(ct);
            using var jsonDocument = await JsonDocument.ParseAsync(responseStream, cancellationToken: ct);
            var root = jsonDocument.RootElement;

            if (!root.TryGetProperty("access_token", out var accessTokenElement)
                || string.IsNullOrWhiteSpace(accessTokenElement.GetString()))
            {
                logger.LogWarning("Keycloak admin token response did not contain an access_token.");
                return null;
            }

            var expiresIn = root.TryGetProperty("expires_in", out var expiresInElement) &&
                            expiresInElement.TryGetInt32(out var seconds)
                ? Math.Max(seconds, 1)
                : 60;

            cachedAccessToken = accessTokenElement.GetString();
            cachedAccessTokenExpiresAt = _timeProvider.GetUtcNow().AddSeconds(expiresIn);

            return cachedAccessToken;
        }
        finally
        {
            _ = tokenLock.Release();
        }
    }

    private bool HasUsableCachedToken()
    {
        return !string.IsNullOrWhiteSpace(cachedAccessToken)
               && cachedAccessTokenExpiresAt > _timeProvider.GetUtcNow().AddSeconds(30);
    }
}
