using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Security.Abstractions.Options;

namespace Sentinel.AspNetCore.Endpoints;

/// <summary>
///     Shared Signals and Events (SSF) Endpoints - RFC 8936 implementation for event-driven security signaling.
///     Receives signed SET (Security Event Token) from upstream IdP (OpenBanking, enterprise)
///     and processes session invalidation, token revocation, credential compromise signals.
/// </summary>
internal static class SsfEndpoints
{
    public static void MapSsfEndpoints(this RouteGroupBuilder group)
    {
        var ssfGroup = group.MapGroup("/ssf").WithTags("Security Event Token");

        ssfGroup.MapPost("/events", ReceiveEventAsync)
            .AllowAnonymous()
            .Produces(StatusCodes.Status202Accepted)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status404NotFound);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Route Handler
    // ─────────────────────────────────────────────────────────────────────────────

    private static async Task<IResult> ReceiveEventAsync(
        HttpRequest request,
        [FromServices] ISsfEventProcessor processor,
        [FromServices] IOptions<SsfOptions> options,
        [FromServices] ILogger<ISsfEventProcessor> logger,
        CancellationToken ct)
    {
        var ssfOptions = options.Value;

        // SSF feature flag - return 404 if disabled (RFC 8936: clients should assume SSF not supported)
        if (!ssfOptions.Enabled)
        {
            return TypedResults.NotFound();
        }

        // Validate authentication token if configured (prevents replay attacks on public endpoint)
        if (ssfOptions.RequireAuthToken && !IsAuthTokenValid(request, ssfOptions))
        {
            return TypedResults.Problem(
                type: "/errors/ssf-auth-failed",
                detail: "SSF authentication failed.",
                statusCode: StatusCodes.Status401Unauthorized);
        }

        var setToken = await ReadSecurityEventTokenAsync(request, ct);
        if (string.IsNullOrWhiteSpace(setToken))
        {
            return TypedResults.Problem(
                "SET token is required. Provide as raw JWT with Content-Type application/secevent+jwt or as 'set' property in JSON.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var result = await processor.ProcessAsync(setToken, ct);
        if (result.IsSuccess)
        {
            return TypedResults.StatusCode(StatusCodes.Status202Accepted);
        }

        logger.LogWarning("SSF event rejected. Unauthorized={Unauthorized}, Error={Error}",
            result.IsUnauthorized, result.Error);

        return result.IsUnauthorized
            ? TypedResults.Problem(
                type: "/errors/ssf-unauthorized",
                detail: result.Error ?? "Invalid SET signature or issuer.",
                statusCode: StatusCodes.Status401Unauthorized)
            : TypedResults.Problem(
                type: "/errors/ssf-processing-failed",
                detail: result.Error ?? "SET processing failed.",
                statusCode: StatusCodes.Status400BadRequest);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────────

    /// <summary>
    ///     Validates SSF-Auth-Token header using constant-time comparison to prevent timing attacks.
    ///     Follows RFC 8936 guidance on SET endpoint authentication.
    /// </summary>
    private static bool IsAuthTokenValid(HttpRequest request, SsfOptions ssfOptions)
    {
        var configuredToken = ssfOptions.AuthToken;
        if (string.IsNullOrWhiteSpace(configuredToken))
        {
            return false;
        }

        var suppliedToken = request.Headers["SSF-Auth-Token"].ToString();
        if (string.IsNullOrWhiteSpace(suppliedToken))
        {
            return false;
        }

        var configuredBytes = Encoding.UTF8.GetBytes(configuredToken);
        var suppliedBytes = Encoding.UTF8.GetBytes(suppliedToken);

        // Constant-time comparison prevents timing side-channel attacks
        return CryptographicOperations.FixedTimeEquals(suppliedBytes, configuredBytes);
    }

    /// <summary>
    ///     Reads SET token from either:
    ///     1. Raw JWT body with Content-Type application/secevent+jwt (RFC 8936)
    ///     2. JSON payload with 'set' property
    /// </summary>
    private static async Task<string?> ReadSecurityEventTokenAsync(HttpRequest request, CancellationToken ct)
    {
        // Handle raw JWT format (Content-Type: application/secevent+jwt)
        if (request.ContentType?.Contains("application/secevent+jwt", StringComparison.OrdinalIgnoreCase) == true)
        {
            using var reader = new StreamReader(request.Body);
            return (await reader.ReadToEndAsync(ct)).Trim();
        }

        // Handle JSON format with 'set' property
        try
        {
            using var payload = await JsonDocument.ParseAsync(request.Body, cancellationToken: ct);
            if (payload.RootElement.TryGetProperty("set", out var setProp))
            {
                return setProp.GetString();
            }

            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
