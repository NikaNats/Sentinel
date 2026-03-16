using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Application.Auth;
using Sentinel.Application.Auth.Models;

namespace Sentinel.Application.DependencyInjection;

public static class ApplicationServiceCollectionExtensions
{
    public static IServiceCollection AddApplicationLayer(this IServiceCollection services)
    {
        services.AddSingleton<IAuthorizationHandler, AcrAuthorizationHandler>();
        services.AddSingleton<IAuthorizationHandler, ScopeAuthorizationHandler>();
        services.AddScoped<IAuthorizationHandler, UmaResourceAuthorizationHandler>();

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
            .AddPolicy(Policies.ReadProfile, policy =>
                policy.RequireAuthenticatedUser()
                    .AddRequirements(
                        new ScopeRequirement("profile"),
                        new AcrRequirement("acr2")))
            .AddPolicy(Policies.RequireAcr3, policy =>
                policy.RequireAuthenticatedUser()
                    .AddRequirements(new AcrRequirement("acr3")))
            .AddPolicy(Policies.DocumentsRead, policy =>
                policy.RequireAuthenticatedUser()
                    .AddRequirements(
                        new ScopeRequirement("documents:read"),
                        new AcrRequirement("acr2")))
            .AddPolicy(Policies.DocumentsWrite, policy =>
                policy.RequireAuthenticatedUser()
                    .AddRequirements(
                        new ScopeRequirement("documents:write"),
                        new AcrRequirement("acr3")));

        return services;
    }
}
