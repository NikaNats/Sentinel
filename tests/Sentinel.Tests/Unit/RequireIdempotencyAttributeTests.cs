using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Sentinel.Middleware.Filters;
using System.Security.Claims;

namespace Sentinel.Tests.Unit;

public sealed class RequireIdempotencyAttributeTests
{
    [Fact]
    public async Task OnActionExecutionAsync_WhenHeaderMissing_ReturnsBadRequest()
    {
        var attribute = new RequireIdempotencyAttribute();
        var context = CreateActionExecutingContext();

        await attribute.OnActionExecutionAsync(context, () => throw new InvalidOperationException("should not execute"));

        var result = Assert.IsType<BadRequestObjectResult>(context.Result);
        Assert.Equal(StatusCodes.Status400BadRequest, result.StatusCode);
    }

    [Fact]
    public async Task OnActionExecutionAsync_WhenDuplicateKey_ReturnsConflict()
    {
        var attribute = new RequireIdempotencyAttribute();
        var context = CreateActionExecutingContext();
        context.HttpContext.Request.Headers["Idempotency-Key"] = "dup-1";

        var cache = context.HttpContext.RequestServices.GetRequiredService<IDistributedCache>();
        await cache.SetStringAsync("idempotency:user-1:dup-1", "processed");

        await attribute.OnActionExecutionAsync(context, () => throw new InvalidOperationException("should not execute"));

        var result = Assert.IsType<ConflictObjectResult>(context.Result);
        Assert.Equal(StatusCodes.Status409Conflict, result.StatusCode);
    }

    [Fact]
    public async Task OnActionExecutionAsync_WhenSuccessfulRequest_StoresIdempotencyKey()
    {
        var attribute = new RequireIdempotencyAttribute();
        var context = CreateActionExecutingContext();
        context.HttpContext.Request.Headers["Idempotency-Key"] = "ok-1";

        await attribute.OnActionExecutionAsync(context, NextOk(context));

        var cache = context.HttpContext.RequestServices.GetRequiredService<IDistributedCache>();
        var cached = await cache.GetStringAsync("idempotency:user-1:ok-1");
        Assert.Equal("processed", cached);
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

    private static ActionExecutingContext CreateActionExecutingContext()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IDistributedCache>(_ =>
            new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())));

        var httpContext = new DefaultHttpContext
        {
            RequestServices = services.BuildServiceProvider(),
            User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-1")], "test"))
        };

        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor(), new ModelStateDictionary());
        return new ActionExecutingContext(actionContext, [], new Dictionary<string, object?>(), controller: new object());
    }
}
