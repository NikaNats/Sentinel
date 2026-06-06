using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Sentinel.Application.Auth.Rar;
using Sentinel.RAR;
using Sentinel.Sample.MinimalApi.Endpoints;

namespace Sentinel.Sample.MinimalApi.Filters;

/// <summary>
///     Domain-specific Rich Authorization Request validation filter for financial transfers.
/// </summary>
public sealed class SurgicalAuthorizationFilter(
    IRarValidator rarValidator,
    ILogger<SurgicalAuthorizationFilter> logger) : IEndpointFilter
{
    private const string FinanceTransferType = "urn:sentinel:finance:transfer";

    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        if (!TryGetTransferRequest(context, out var request))
        {
            return TypedResults.Problem(
                type: "/errors/invalid-request",
                title: "Invalid Request Payload",
                detail: "TransferRequest could not be extracted from the request body.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var details = context.HttpContext.User.GetAuthorizationDetails();
        var payloadJson = JsonSerializer.Serialize(request, SampleJsonContext.Default.TransferRequest);
        var validationResult = rarValidator.ValidateByType(details, FinanceTransferType, payloadJson);

        if (validationResult.IsValid)
        {
            return await next(context);
        }

        logger.LogWarning(
            "RAR_VALIDATION_FAILED: Type {AuthorizationDetailType}. Error: {Error}",
            FinanceTransferType,
            validationResult.Error);

        return TypedResults.Problem(
            type: "/errors/authorization-bounds-exceeded",
            title: "Authorization Bounds Exceeded",
            detail: validationResult.Error ?? "The request payload violates signed authorization constraints.",
            statusCode: StatusCodes.Status403Forbidden);
    }

    private static bool TryGetTransferRequest(
        EndpointFilterInvocationContext context,
        [NotNullWhen(true)] out TransferRequest? request)
    {
        for (var i = 0; i < context.Arguments.Count; i++)
        {
            if (context.Arguments[i] is TransferRequest candidate)
            {
                request = candidate;
                return true;
            }
        }

        request = null;
        return false;
    }
}
