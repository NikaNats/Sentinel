using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.AspNetCore.Errors;

namespace Sentinel.AspNetCore.Endpoints;

/// <summary>
///     Token Exchange Endpoints - OAuth 2.0 Token Exchange (RFC 8693) implementation for external IdP federation.
///     Supports ExternalToken (JWT/SAML) → SentinelToken transformation with DPoP binding.
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
                "External token, provider name, and code verifier are required.",
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
                "Token exchange failed.",
                statusCode: StatusCodes.Status401Unauthorized);
        }

        return TypedResults.Ok(new TokenExchangeResponseDto(
            result.AccessToken,
            result.RefreshToken,
            result.TokenType ?? "DPoP",
            result.ExpiresIn,
            result.Scope));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // DTOs
    // ─────────────────────────────────────────────────────────────────────────────

    public sealed record TokenExchangeRequest(string ExternalToken, string ProviderName, string CodeVerifier);

    public sealed record TokenExchangeResponseDto(
        [property: System.Text.Json.Serialization.JsonPropertyName("access_token")] string AccessToken,
        [property: System.Text.Json.Serialization.JsonPropertyName("refresh_token")] string? RefreshToken,
        [property: System.Text.Json.Serialization.JsonPropertyName("token_type")] string TokenType,
        [property: System.Text.Json.Serialization.JsonPropertyName("expires_in")] int ExpiresIn,
        [property: System.Text.Json.Serialization.JsonPropertyName("scope")] string? Scope);
}
