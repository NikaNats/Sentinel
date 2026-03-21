using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Sentinel.Application.Auth.Rar;
using Sentinel.Controllers;
using Sentinel.Errors;

namespace Sentinel.Middleware.Filters;

[AttributeUsage(AttributeTargets.Method)]
public sealed class RequireSurgicalAuthorizationAttribute : Attribute, IAsyncActionFilter
{
    private const string TransferAuthorizationType = "urn:sentinel:finance:transfer";

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var details = context.HttpContext.User.GetAuthorizationDetails();
        var transferDetail =
            details.FirstOrDefault(x => string.Equals(x.Type, TransferAuthorizationType, StringComparison.Ordinal));

        if (transferDetail is null)
        {
            context.Result = new ObjectResult(new ProblemDetails
            {
                Type = ErrorCodes.MissingAuthorizationDetail,
                Title = "Surgical Authorization Required",
                Detail = "This endpoint requires a transfer authorization_detail.",
                Status = StatusCodes.Status403Forbidden
            })
            {
                StatusCode = StatusCodes.Status403Forbidden
            };
            return;
        }

        if (context.ActionArguments.Values.FirstOrDefault(x => x is FinanceController.TransferRequest)
            is not FinanceController.TransferRequest request)
        {
            context.Result = new BadRequestObjectResult(new ProblemDetails
            {
                Type = ErrorCodes.InvalidRequest,
                Title = "Invalid request payload",
                Status = StatusCodes.Status400BadRequest
            });
            return;
        }

        // 2026 best practice: Use precision-safe decimal comparison (0.0001m tolerance for financial data)
        if (transferDetail.Amount == null || Math.Abs(transferDetail.Amount.Value - request.Amount) > 0.0001m
            || !string.Equals(transferDetail.Currency, request.Currency, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(transferDetail.TransactionId, request.TransactionId, StringComparison.Ordinal))
        {
            context.Result = new ObjectResult(new ProblemDetails
            {
                Type = ErrorCodes.AuthorizationBoundsExceeded,
                Title = "Authorization Bounds Exceeded",
                Detail = "Request payload does not match token authorization bounds.",
                Status = StatusCodes.Status403Forbidden
            })
            {
                StatusCode = StatusCodes.Status403Forbidden
            };
            return;
        }

        await next();
    }
}
