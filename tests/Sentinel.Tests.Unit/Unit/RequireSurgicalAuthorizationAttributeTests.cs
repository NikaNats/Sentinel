using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Controllers;
using Sentinel.Middleware.Filters;
using System.Security.Claims;

namespace Sentinel.Tests.Unit;

public sealed class RequireSurgicalAuthorizationAttributeTests
{
    [Fact]
    public async Task OnActionExecutionAsync_WhenAuthorizationDetailsMissing_ReturnsForbidden()
    {
        var attribute = new RequireSurgicalAuthorizationAttribute();
        var context = CreateActionExecutingContext(
            user: new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-1")], "test")),
            request: new FinanceController.TransferRequest("txn-1", 50m, "GEL", "dest-1"));

        await attribute.OnActionExecutionAsync(context, () => throw new InvalidOperationException("should not execute"));

        var result = Assert.IsType<ObjectResult>(context.Result);
        Assert.Equal(StatusCodes.Status403Forbidden, result.StatusCode);
    }

    [Fact]
    public async Task OnActionExecutionAsync_WhenTransferDoesNotMatchTokenBounds_ReturnsForbidden()
    {
        var attribute = new RequireSurgicalAuthorizationAttribute();
        var user = CreateUserWithRar("""
            [{"type":"urn:sentinel:finance:transfer","transaction_id":"txn-1","amount":50.00,"currency":"GEL"}]
            """);
        var context = CreateActionExecutingContext(
            user,
            new FinanceController.TransferRequest("txn-1", 500m, "GEL", "dest-1"));

        await attribute.OnActionExecutionAsync(context, () => throw new InvalidOperationException("should not execute"));

        var result = Assert.IsType<ObjectResult>(context.Result);
        Assert.Equal(StatusCodes.Status403Forbidden, result.StatusCode);
    }

    [Fact]
    public async Task OnActionExecutionAsync_WhenRequestMissing_ReturnsBadRequest()
    {
        var attribute = new RequireSurgicalAuthorizationAttribute();
        var user = CreateUserWithRar("""
            [{"type":"urn:sentinel:finance:transfer","transaction_id":"txn-1","amount":50.00,"currency":"GEL"}]
            """);
        var context = CreateActionExecutingContext(user, request: null);

        await attribute.OnActionExecutionAsync(context, () => throw new InvalidOperationException("should not execute"));

        var result = Assert.IsType<BadRequestObjectResult>(context.Result);
        Assert.Equal(StatusCodes.Status400BadRequest, result.StatusCode);
    }

    [Fact]
    public async Task OnActionExecutionAsync_WhenTransferMatchesTokenBounds_ExecutesNext()
    {
        var attribute = new RequireSurgicalAuthorizationAttribute();
        var user = CreateUserWithRar("""
            [{"type":"urn:sentinel:finance:transfer","transaction_id":"txn-1","amount":50.00,"currency":"GEL"}]
            """);
        var context = CreateActionExecutingContext(
            user,
            new FinanceController.TransferRequest("txn-1", 50m, "gel", "dest-1"));

        await attribute.OnActionExecutionAsync(context, NextOk(context));

        Assert.Null(context.Result);
    }

    private static ClaimsPrincipal CreateUserWithRar(string authorizationDetails)
    {
        return new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "user-1"),
            new Claim("authorization_details", authorizationDetails)
        ], "test"));
    }

    private static ActionExecutionDelegate NextOk(ActionExecutingContext context)
    {
        return () =>
        {
            var executed = new ActionExecutedContext(context, context.Filters, context.Controller)
            {
                Result = new OkObjectResult(new { status = "ok" })
            };
            return Task.FromResult(executed);
        };
    }

    private static ActionExecutingContext CreateActionExecutingContext(
        ClaimsPrincipal user,
        FinanceController.TransferRequest? request)
    {
        var httpContext = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection().BuildServiceProvider(),
            User = user
        };

        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor(), new ModelStateDictionary());
        var actionArguments = new Dictionary<string, object?>();
        if (request is not null)
        {
            actionArguments["request"] = request;
        }

        return new ActionExecutingContext(actionContext, [], actionArguments, controller: new object());
    }
}
