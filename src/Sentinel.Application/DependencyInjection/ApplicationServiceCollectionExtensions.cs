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

        services.AddAuthorization(options =>
        {
            options.DefaultPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .RequireClaim("acr")
                .Build();

            options.AddPolicy(Policies.ElevatedAccess, policy =>
                policy.RequireAuthenticatedUser()
                    .RequireClaim("acr", "acr3")
                    .RequireAssertion(context =>
                    {
                        var clearance = context.User.FindFirst("security_clearance")?.Value;
                        return clearance is "top-secret" or "classified";
                    }));

            options.AddPolicy(Policies.ReadProfile, policy =>
                policy.RequireAuthenticatedUser()
                    .AddRequirements(
                        new ScopeRequirement("profile"),
                        new AcrRequirement("acr2")));

            options.AddPolicy(Policies.RequireAcr3, policy =>
                policy.RequireAuthenticatedUser()
                    .AddRequirements(new AcrRequirement("acr3")));

            options.AddPolicy(Policies.DocumentRead, policy =>
                policy.RequireAuthenticatedUser()
                    .AddRequirements(new UmaResourceRequirement("document:read")));

            options.AddPolicy(Policies.DocumentDelete, policy =>
                policy.RequireAuthenticatedUser()
                    .AddRequirements(new UmaResourceRequirement("document:delete")));
        });

        return services;
    }
}
