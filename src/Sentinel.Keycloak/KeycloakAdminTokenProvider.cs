// Sentinel Security API - FAPI 2.0 Compliant

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

    private TokenSnapshot? cachedToken;

    public void Dispose()
    {
        tokenLock.Dispose();
    }

    public async Task<string?> GetAccessTokenAsync(CancellationToken ct)
    {
        if (TryGetUsableCachedToken(out var token))
        {
            return token;
        }

        await tokenLock.WaitAsync(ct);
        try
        {
            if (TryGetUsableCachedToken(out token))
            {
                return token;
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
            HttpResponseMessage response;

            try
            {
                response = await adminHttpClient.SendAsync(request, ct);
            }
            catch (HttpRequestException ex)
            {
                logger.LogWarning(ex, "Failed to reach Keycloak token endpoint for admin token acquisition.");
                return null;
            }
            catch (TaskCanceledException ex) when (!ct.IsCancellationRequested)
            {
                logger.LogWarning(ex, "Timed out while acquiring Keycloak admin token.");
                return null;
            }

            using (response)
            {
                if (!response.IsSuccessStatusCode)
                {
                    logger.LogWarning("Failed to acquire Keycloak admin token. Status code: {StatusCode}",
                        (int)response.StatusCode);
                    return null;
                }

                await using var responseStream = await response.Content.ReadAsStreamAsync(ct);
                JsonElement root;
                try
                {
                    using var jsonDocument = await JsonDocument.ParseAsync(responseStream, cancellationToken: ct);
                    root = jsonDocument.RootElement.Clone();
                }
                catch (JsonException ex)
                {
                    logger.LogWarning(ex, "Keycloak admin token response body was not valid JSON.");
                    return null;
                }

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

                var snapshot = new TokenSnapshot(accessTokenElement.GetString()!,
                    _timeProvider.GetUtcNow().AddSeconds(expiresIn));
                Volatile.Write(ref cachedToken, snapshot);

                return snapshot.AccessToken;
            }
        }
        finally
        {
            _ = tokenLock.Release();
        }
    }

    private bool TryGetUsableCachedToken(out string? token)
    {
        var snapshot = Volatile.Read(ref cachedToken);
        if (snapshot is null)
        {
            token = null;
            return false;
        }

        if (snapshot.ExpiresAtUtc <= _timeProvider.GetUtcNow().AddSeconds(30))
        {
            token = null;
            return false;
        }

        token = snapshot.AccessToken;
        return true;
    }

    private sealed record TokenSnapshot(string AccessToken, DateTimeOffset ExpiresAtUtc);
}
