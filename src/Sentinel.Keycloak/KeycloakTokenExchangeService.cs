using System.Net.Http.Json;
using Microsoft.Extensions.Options;
using Sentinel.Application;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;

namespace Sentinel.Keycloak;

public sealed class KeycloakTokenExchangeService(
    HttpClient httpClient,
    IOptions<KeycloakOptions> options,
    ILogger<KeycloakTokenExchangeService> logger) : ITokenExchangeService
{
    private readonly KeycloakOptions keycloakOptions = options.Value;

    public async Task<TokenExchangeResult?> ExchangeExternalTokenAsync(string externalToken, string providerName,
        string dpopProof, string codeVerifier, CancellationToken ct)
    {
        var authority = keycloakOptions.Authority.TrimEnd('/');
        var audience = keycloakOptions.Audience;

        if (string.IsNullOrWhiteSpace(authority)
            || string.IsNullOrWhiteSpace(audience)
            || string.IsNullOrWhiteSpace(externalToken)
            || string.IsNullOrWhiteSpace(providerName)
            || string.IsNullOrWhiteSpace(dpopProof)
            || string.IsNullOrWhiteSpace(codeVerifier))
        {
            return null;
        }

        var tokenEndpoint = $"{authority}/protocol/openid-connect/token";
        var body = new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
            new KeyValuePair<string, string>("client_id", audience),
            new KeyValuePair<string, string>("subject_token", externalToken),
            new KeyValuePair<string, string>("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
            new KeyValuePair<string, string>("subject_issuer", providerName),
            new KeyValuePair<string, string>("code_verifier", codeVerifier),
            new KeyValuePair<string, string>("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
        ]);

        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint) { Content = body };
        request.Headers.Add("DPoP", dpopProof);

        try
        {
            using var response = await httpClient.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("Token exchange failed with status {StatusCode} for provider {Provider}.",
                    (int)response.StatusCode, providerName);
                return null;
            }

            return await response.Content.ReadFromJsonAsync(
                ApplicationJsonContext.Default.TokenExchangeResult,
                ct);
        }
#pragma warning disable CA1031 // Intentional catch-all: token exchange failures return null to keep auth endpoint fail-closed.
        catch (Exception ex)
        {
            logger.LogError(ex, "Token exchange failed for provider {Provider}.", providerName);
            return null;
        }
#pragma warning restore CA1031
    }
}
