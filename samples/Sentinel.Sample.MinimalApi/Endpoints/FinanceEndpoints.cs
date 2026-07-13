using Sentinel.AspNetCore.Endpoints;
using Sentinel.Sample.MinimalApi.Filters;

namespace Sentinel.Sample.MinimalApi.Endpoints;

/// <summary>
///     Simple finance transfer contract secured by Sentinel's policy pipeline.
/// </summary>
public sealed record TransferRequest(
    string TransactionId,
    decimal Amount,
    string Currency,
    string DestinationAccount);

public sealed record TransferResponse(
    string Status,
    string TransactionId,
    string Message,
    DateTimeOffset ProcessedAtUtc);

internal static class FinanceEndpoints
{
    public static void MapFinanceEndpoints(this IEndpointRouteBuilder routes, string prefix)
    {
        var group = routes.MapGroup(prefix)
            .RequireAuthorization()
            .WithTags("Finance");

        group.MapPost("/transfer", ExecuteTransfer)
            .WithName("ExecuteTransfer")
            .Accepts<TransferRequest>("application/json")
            .Produces<TransferResponse>()
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status409Conflict)
            .RequireAcrStepUp("acr3", TimeSpan.FromMinutes(5))
            .RequireIdempotency()
            .AddEndpointFilter<SurgicalAuthorizationFilter>();
    }

    private static IResult ExecuteTransfer(
        TransferRequest request,
        HttpContext context,
        CancellationToken ct)
    {
        _ = ct;

        var sub = context.User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(sub))
        {
            return TypedResults.Unauthorized();
        }

        if (string.IsNullOrWhiteSpace(request.TransactionId))
        {
            return TypedResults.Problem(
                type: "/errors/invalid-request",
                title: "Invalid transfer request",
                detail: "TransactionId is required.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        if (request.Amount <= 0)
        {
            return TypedResults.Problem(
                type: "/errors/invalid-request",
                title: "Invalid transfer request",
                detail: "Amount must be greater than zero.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        if (!IsCurrencyCode(request.Currency))
        {
            return TypedResults.Problem(
                type: "/errors/invalid-request",
                title: "Invalid transfer request",
                detail: "Currency must be a 3-letter ISO 4217 code.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        if (string.IsNullOrWhiteSpace(request.DestinationAccount))
        {
            return TypedResults.Problem(
                type: "/errors/invalid-request",
                title: "Invalid transfer request",
                detail: "DestinationAccount is required.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        return TypedResults.Ok(new TransferResponse(
            "Approved",
            request.TransactionId,
            $"Transfer of {request.Amount} {request.Currency.ToUpperInvariant()} to {request.DestinationAccount} accepted.",
            DateTimeOffset.UtcNow));
    }

    private static bool IsCurrencyCode(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length != 3)
        {
            return false;
        }

        foreach (var c in value.AsSpan())
        {
            if (!char.IsAsciiLetter(c))
            {
                return false;
            }
        }

        return true;
    }
}
