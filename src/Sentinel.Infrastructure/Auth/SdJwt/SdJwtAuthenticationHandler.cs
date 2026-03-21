using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Sentinel.Application.Auth.Interfaces;

namespace Sentinel.Infrastructure.Auth.SdJwt;

public sealed class SdJwtAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IOptions<KeycloakOptions> keycloakOptions,
    IOptions<SdJwtOptions> sdJwtOptions,
    ISdJwtVerifier verifier) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    private readonly KeycloakOptions keycloak = keycloakOptions.Value;
    private readonly SdJwtOptions sdOptions = sdJwtOptions.Value;

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!sdOptions.Enabled)
        {
            return AuthenticateResult.NoResult();
        }

        if (!Request.Headers.TryGetValue("Authorization", out var authHeaders))
        {
            return AuthenticateResult.NoResult();
        }

        var token = authHeaders.ToString();
        if (token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            token = token["Bearer ".Length..].Trim();
        }
        else if (token.StartsWith("SD-JWT ", StringComparison.OrdinalIgnoreCase))
        {
            token = token["SD-JWT ".Length..].Trim();
        }

        if (!token.Contains('~', StringComparison.Ordinal))
        {
            return AuthenticateResult.NoResult();
        }

        var expectedNonce = Request.Headers["SD-JWT-Nonce"].ToString();
        var result = await verifier.VerifyPresentationAsync(token, keycloak.Audience, expectedNonce, Context.RequestAborted);
        if (!result.IsSuccess || result.Principal is null)
        {
            return AuthenticateResult.Fail(result.Error ?? "SD-JWT verification failed.");
        }

        var ticket = new AuthenticationTicket(result.Principal, Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }
}
