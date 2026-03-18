using System.Net.Http.Json;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;

namespace Sentinel.Infrastructure.Auth;

public sealed class KeycloakTokenExchangeService(
    HttpClient httpClient,
    IConfiguration configuration,
    ILogger<KeycloakTokenExchangeService> logger) : ITokenExchangeService
{
    public async Task<TokenExchangeResult?> ExchangeExternalTokenAsync(string externalToken, string providerName, string dpopProof, CancellationToken ct)
    {
        var authority = configuration["Keycloak:Authority"]?.TrimEnd('/');
        var audience = configuration["Keycloak:Audience"];

        if (string.IsNullOrWhiteSpace(authority)
            || string.IsNullOrWhiteSpace(audience)
            || string.IsNullOrWhiteSpace(externalToken)
            || string.IsNullOrWhiteSpace(providerName)
            || string.IsNullOrWhiteSpace(dpopProof))
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
            new KeyValuePair<string, string>("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
        ]);

        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint) { Content = body };
        request.Headers.Add("DPoP", dpopProof);

        try
        {
            using var response = await httpClient.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("Token exchange failed with status {StatusCode} for provider {Provider}.", (int)response.StatusCode, providerName);
                return null;
            }

            return await response.Content.ReadFromJsonAsync<TokenExchangeResult>(cancellationToken: ct);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Token exchange failed for provider {Provider}.", providerName);
            return null;
        }
    }
}
