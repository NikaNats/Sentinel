// Sentinel Security API - FAPI 2.0 Compliant

namespace Sentinel.Keycloak.Dpop;

/// <summary>
///     Attaches a DPoP proof to outbound token-endpoint requests. Proofs
///     supplied by callers (e.g. a browser-held key forwarded for refresh) are
///     preserved; only requests without a DPoP header are signed with the
///     process proof key.
/// </summary>
public sealed class DpopProofDelegatingHandler(KeycloakDpopProofFactory proofFactory) : DelegatingHandler
{
    private readonly KeycloakDpopProofFactory _proofFactory = proofFactory;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        if (!request.Headers.Contains("DPoP"))
        {
            request.Headers.Add("DPoP",
                _proofFactory.CreateProof(request.Method.Method, request.RequestUri!.AbsoluteUri));
        }

        return await base.SendAsync(request, cancellationToken);
    }
}