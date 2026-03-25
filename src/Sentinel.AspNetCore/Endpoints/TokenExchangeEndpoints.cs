using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.AspNetCore.Errors;

namespace Sentinel.AspNetCore.Endpoints;

/// <summary>
/// Token Exchange Endpoints - OAuth 2.0 Token Exchange (RFC 8693) implementation for external IdP federation.
/// Supports ExternalToken (JWT/SAML) → SentinelToken transformation with DPoP binding.
/// </summary>
internal static class TokenExchangeEndpoints
{
    public static void MapTokenExchangeEndpoints(this RouteGroupBuilder group)
    {
        var exchangeGroup = group.MapGroup("/auth").WithTags("Token Exchange");

        exchangeGroup.MapPost("/token-exchange", ExchangeExternalTokenAsync)
            .AllowAnonymous()
            .WithName("ExchangeExternalToken")
            .Produces(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status401Unauthorized);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Route Handler
    // ─────────────────────────────────────────────────────────────────────────────

    private static async Task<IResult> ExchangeExternalTokenAsync(
        [FromBody] TokenExchangeRequest request,
        [FromHeader(Name = "DPoP")] string? dpopProof,
        [FromServices] ITokenExchangeService tokenExchangeService,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.ExternalToken)
            || string.IsNullOrWhiteSpace(request.ProviderName)
            || string.IsNullOrWhiteSpace(request.CodeVerifier))
        {
            return TypedResults.Problem(
                detail: "External token, provider name, and code verifier are required.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        if (string.IsNullOrWhiteSpace(dpopProof))
        {
            return TypedResults.Problem(
                type: ErrorCodes.MissingDpopProof,
                detail: "DPoP proof is required.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var result = await tokenExchangeService.ExchangeExternalTokenAsync(
            request.ExternalToken,
            request.ProviderName,
            dpopProof,
            request.CodeVerifier,
            ct);

        if (result is null || string.IsNullOrWhiteSpace(result.AccessToken))
        {
            return TypedResults.Problem(
                detail: "Token exchange failed.",
                statusCode: StatusCodes.Status401Unauthorized);
        }

        return TypedResults.Ok(new
        {
            access_token = result.AccessToken,
            refresh_token = result.RefreshToken,
            token_type = result.TokenType,
            expires_in = result.ExpiresIn,
            scope = result.Scope
        });
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // DTOs
    // ─────────────────────────────────────────────────────────────────────────────

    public sealed record TokenExchangeRequest(string ExternalToken, string ProviderName, string CodeVerifier);
}
