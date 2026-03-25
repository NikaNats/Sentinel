using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Sentinel.AspNetCore.Endpoints;
using Sentinel.Sample.MinimalApi.Filters;

namespace Sentinel.Sample.MinimalApi.Endpoints;

/// <summary>
/// Finance Domain Endpoints
///
/// Demonstrates enterprise-grade transaction security combining:
/// - ACR Step-Up (Hardware MFA required for high-value transfers)
/// - Rich Authorization Requests (Limits certified within the token)
/// - Idempotency (Prevents duplicate fund transfers)
/// - RFC 7807 Problem Details (Structured error responses)
/// </summary>
public sealed record TransferRequest(
    string TransactionId,
    decimal Amount,
    string Currency,
    string DestinationAccount);

public sealed record TransferResponse(
    string Status,
    string TransactionId,
    string Message);

internal static class FinanceEndpoints
{
    public static void MapFinanceEndpoints(this IEndpointRouteBuilder routes, string prefix)
    {
        var group = routes.MapGroup(prefix)
            .RequireAuthorization()
            .WithTags("Finance");

        // ─────────────────────────────────────────────────────────────────────────
        // POST /api/v1/finance/transfer - Execute fund transfer
        // ─────────────────────────────────────────────────────────────────────────
        // Security requirements:
        // 1. Bearer token with ACR3 claim (Hardware MFA used < 5 minutes ago)
        //    - If token only has ACR2 → Framework returns 401 with acr_values=acr3 challenge
        // 2. Valid DPoP proof binding the request to the token's JKT
        // 3. Idempotency-Key header (128-bit UUID, prevents duplicate RPC)
        // 4. Request body must match signed RAR bounds in token
        // ─────────────────────────────────────────────────────────────────────────

        group.MapPost("/transfer", ExecuteTransfer)
            .WithName("ExecuteTransfer")
            .Accepts<TransferRequest>("application/json")
            .Produces<TransferResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status202Accepted)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized) // Missing ACR3 or DPoP
            .Produces(StatusCodes.Status403Forbidden)    // RAR bounds exceeded or mTLS mismatch
            .Produces(StatusCodes.Status409Conflict)     // Idempotency key collision
            // SECURITY LAYER 1: Require ACR3 (NIST AAL 3 = Hardware MFA)
            .RequireAuthorization(policy =>
                policy.RequireClaim("acr", "acr3"))
            // SECURITY LAYER 2: Enforce Idempotency-Key (RFC 9110)
            .RequireIdempotency()
            // SECURITY LAYER 3: Custom business-logic RAR validation
            // Compares request body against token's signed authorization_details
            .AddEndpointFilter<SurgicalAuthorizationFilter>();
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // HANDLER: Execute Transfer
    // ─────────────────────────────────────────────────────────────────────────────
    /// <summary>
    /// Execute a fund transfer. By the time this handler executes:
    ///
    /// ✅ VERIFIED:
    /// - User has authenticated with Hardware MFA (ACR3 certified within 5 min)
    /// - DPoP proof matches the JKT in the token
    /// - Idempotency-Key is unique (Redis lock acquired, no duplicates)
    /// - Request payload exactly matches the RAR bounds signed by the IdP
    ///
    /// In a real system, this would:
    /// 1. Begin a database transaction
    /// 2. Debit source account
    /// 3. Credit destination account
    /// 4. Log the audit trail (immutable, for compliance)
    /// 5. Return 200 OK
    ///
    /// On duplicate Idempotency-Key:
    /// - Framework returns 204 No Content (cached response)
    /// - Prevents double-charging the account
    /// </summary>
    private static IResult ExecuteTransfer(
        TransferRequest request,
        HttpContext context,
        CancellationToken ct)
    {
        var sub = context.User.FindFirst("sub")?.Value;
        if (sub == null)
            return TypedResults.Unauthorized();

        // In production:
        // var result = await bankingService.TransferAsync(sub, request, ct);
        // if (!result.IsSuccess)
        //     return TypedResults.Problem(...);

        // This sample always succeeds
        return TypedResults.Ok(new TransferResponse(
            Status: "Success",
            TransactionId: request.TransactionId,
            Message: $"Transferred {request.Amount} {request.Currency} to {request.DestinationAccount} securely."));
    }
}
