using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Sentinel.Application.Auth.Rar;

namespace Sentinel.Sample.MinimalApi.Filters;

/// <summary>
/// Domain-Specific Rich Authorization Request (RAR) Validation Filter
///
/// RFC 9396 Rich Authorization Requests enable cryptographically signed delegation
/// of specific transaction details. This filter compares the HTTP request body
/// against the signed authorization_details claims in the JWT token.
///
/// Use case: Financial transfers where the token says "transfer up to $50,000"
/// but the request body says "$100,000" → DENIED. Mismatches are caught before
/// the handler executes, preventing unauthorized transactions.
/// </summary>
public sealed class SurgicalAuthorizationFilter(ILogger<SurgicalAuthorizationFilter> logger) : IEndpointFilter
{
    private const string FinanceTransferType = "urn:sentinel:finance:transfer";

    /// <summary>
    /// Invoked before the endpoint handler.
    /// Extracts signed authorization_details from token and validates request body
    /// matches the bounds.
    /// </summary>
    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        // Step 1: Extract RAR claims from JWT
        var details = context.HttpContext.User.GetAuthorizationDetails();
        var transferDetail = details.FirstOrDefault(x =>
            string.Equals(x.Type, FinanceTransferType, StringComparison.Ordinal));

        if (transferDetail is null)
        {
            return TypedResults.Problem(
                type: "/errors/missing-authorization-detail",
                title: "Surgical Authorization Required",
                detail: $"This endpoint requires a '{FinanceTransferType}' authorization_detail signed in the token.",
                statusCode: StatusCodes.Status403Forbidden);
        }

        // Step 2: Extract TransferRequest from endpoint arguments
        var request = context.Arguments
            .OfType<Endpoints.TransferRequest>()
            .FirstOrDefault();

        if (request is null)
        {
            return TypedResults.Problem(
                type: "/errors/invalid-request",
                title: "Invalid Request Payload",
                detail: "TransferRequest could not be extracted from the request body.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        // Step 3: Validate request body matches signed bounds
        // All three fields must match exactly:
        // - Amount (with precision-safe decimal comparison)
        // - Currency (case-insensitive)
        // - TransactionId (case-sensitive UUID)

        if (transferDetail.Amount == null)
        {
            return TypedResults.Problem(
                type: "/errors/authorization-detail-malformed",
                title: "Missing Amount in Authorization Detail",
                detail: "The authorization_details claim does not contain an 'amount' field.",
                statusCode: StatusCodes.Status403Forbidden);
        }

        // Precision-safe decimal comparison: allow 0.01 cent tolerance
        const decimal epsilon = 0.0001m;
        bool amountMatches = Math.Abs(transferDetail.Amount.Value - request.Amount) < epsilon;
        bool currencyMatches = string.Equals(
            transferDetail.Currency,
            request.Currency,
            StringComparison.OrdinalIgnoreCase);
        bool transactionIdMatches = string.Equals(
            transferDetail.TransactionId,
            request.TransactionId,
            StringComparison.Ordinal);

        if (!amountMatches || !currencyMatches || !transactionIdMatches)
        {
            logger.LogWarning(
            "AUTHORIZATION_BOUNDS_EXCEEDED: Token bound to Txn: {ExpectedTxn}, Amount: {ExpectedAmount} {ExpectedCurrency}. Request attempted Txn: {ActualTxn}, Amount: {ActualAmount} {ActualCurrency}.",
            transferDetail.TransactionId,
            transferDetail.Amount,
            transferDetail.Currency,
            request.TransactionId,
            request.Amount,
            request.Currency);

            return TypedResults.Problem(
                type: "/errors/authorization-bounds-exceeded",
                title: "Authorization Bounds Exceeded",
            detail: "The request payload violates the cryptographic authorization constraints signed into the token.",
                statusCode: StatusCodes.Status403Forbidden);
        }

        // Step 4: If we reach here, all bounds match → allow handler to execute
        return await next(context);
    }
}
