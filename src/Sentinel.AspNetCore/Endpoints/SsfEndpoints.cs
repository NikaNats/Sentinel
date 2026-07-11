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
        [FromServices] IOptionsMonitor<SsfOptions> optionsMonitor,
        [FromServices] ILoggerFactory loggerFactory,
        CancellationToken ct)
    {
        var logger = loggerFactory.CreateLogger("Sentinel.AspNetCore.Endpoints.SsfEndpoints");
        var ssfOptions = optionsMonitor.CurrentValue;

        // SSF feature flag - return 404 if disabled (RFC 8936: clients should assume SSF not supported)
        if (!ssfOptions.Enabled)
        {
            return TypedResults.NotFound();
        }

        // Validate authentication token if configured (prevents replay attacks on public endpoint)
        if (ssfOptions.RequireAuthToken && !IsAuthTokenValid(request, ssfOptions))
        {
            logger.LogWarning("security:ssf_auth_failed SSF Webhook token verification failed.");
            return TypedResults.NotFound(); // Route obfuscation: obfuscating endpoint existence
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
    ///     Validates SSF-Auth-Token header using secure, zero-allocation SHA-256 length normalization
    ///     and constant-time comparison to mathematically eliminate timing side-channel attacks.
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

        var maxConfiguredBytes = Encoding.UTF8.GetMaxByteCount(configuredToken.Length);
        var maxSuppliedBytes = Encoding.UTF8.GetMaxByteCount(suppliedToken.Length);

        var configuredBytes = maxConfiguredBytes <= 512
            ? stackalloc byte[maxConfiguredBytes]
            : new byte[maxConfiguredBytes];
        var suppliedBytes = maxSuppliedBytes <= 512 ? stackalloc byte[maxSuppliedBytes] : new byte[maxSuppliedBytes];

        var configuredLen = Encoding.UTF8.GetBytes(configuredToken, configuredBytes);
        var suppliedLen = Encoding.UTF8.GetBytes(suppliedToken, suppliedBytes);

        Span<byte> configuredHash = stackalloc byte[32];
        Span<byte> suppliedHash = stackalloc byte[32];

        SHA256.HashData(configuredBytes[..configuredLen], configuredHash);
        SHA256.HashData(suppliedBytes[..suppliedLen], suppliedHash);

        return CryptographicOperations.FixedTimeEquals(configuredHash, suppliedHash);
    }

    /// <summary>
    ///     Reads SET token from either:
    ///     1. Raw JWT body with Content-Type application/secevent+jwt (RFC 8936)
    ///     2. JSON payload with 'set' property
    /// </summary>
    private static async Task<string?> ReadSecurityEventTokenAsync(HttpRequest request, CancellationToken ct)
    {
        if (request.ContentType?.Contains("application/secevent+jwt", StringComparison.OrdinalIgnoreCase) == true)
        {
            using var reader = new StreamReader(request.Body);
            return (await reader.ReadToEndAsync(ct)).Trim();
        }

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
