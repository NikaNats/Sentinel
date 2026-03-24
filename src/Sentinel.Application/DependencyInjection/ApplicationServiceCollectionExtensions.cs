using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Application.Auth;
using Sentinel.Application.Auth.Interfaces;

namespace Sentinel.Application.DependencyInjection;

public static class ApplicationServiceCollectionExtensions
{
    public static IServiceCollection AddApplicationLayer(this IServiceCollection services)
    {
        services.AddSingleton<IAuthorizationHandler, ScopeAuthorizationHandler>();

        services.AddAuthorizationBuilder()
            .SetDefaultPolicy(new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .RequireClaim("acr")
                .Build())
            .AddPolicy(Policies.ElevatedAccess, policy =>
                policy.RequireAuthenticatedUser()
                    .RequireClaim("acr", "acr3")
                    .RequireAssertion(context =>
                    {
                        var clearance = context.User.FindFirst("security_clearance")?.Value;
                        return clearance is "top-secret" or "classified";
                    }))
            .AddPolicy(Policies.RequireAcr3, policy =>
                policy.RequireAuthenticatedUser()
                    .AddRequirements(new AcrRequirement("acr3")));

        return services;
    }
}

