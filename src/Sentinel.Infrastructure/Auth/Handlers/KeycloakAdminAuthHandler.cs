using System.Net;
using System.Net.Http.Headers;
using Sentinel.Keycloak;

namespace Sentinel.Infrastructure.Auth.Handlers;

/// <summary>
///     Injects Keycloak admin bearer tokens into outgoing admin API requests.
/// </summary>
internal sealed class KeycloakAdminAuthHandler(KeycloakAdminTokenProvider tokenProvider) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var token = await tokenProvider.GetAccessTokenAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(token))
        {
            return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
            {
                RequestMessage = request,
                ReasonPhrase = "Identity Provider Admin Token Unavailable"
            };
        }

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await base.SendAsync(request, cancellationToken);
    }
}
