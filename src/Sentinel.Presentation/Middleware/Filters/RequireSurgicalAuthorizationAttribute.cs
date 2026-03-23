using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Sentinel.Application.Auth.Rar;
using Sentinel.Errors;

namespace Sentinel.Middleware.Filters;

[AttributeUsage(AttributeTargets.Method)]
public sealed class RequireSurgicalAuthorizationAttribute : Attribute, IAsyncActionFilter
{
    // This attribute has been moved to Sentinel.SampleHost as it is domain-specific to the Finance transfer authorization
    // Please use Sentinel.SampleHost.Middleware.Filters.RequireSurgicalAuthorizationAttribute instead
    
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        // Stub implementation - routing to sample host implementation
        // Framework users should reference the SampleHost version for their domain functions
        await next();
    }
}

