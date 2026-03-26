using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Application.Auth;
using Sentinel.Application.Auth.Handlers;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Application.Auth.Options;
using Sentinel.Security.Abstractions.Options;

namespace Sentinel.Application.DependencyInjection;

public static class ApplicationServiceCollectionExtensions
{
    public static IServiceCollection AddApplicationLayer(this IServiceCollection services)
    {
        // When called without configuration, register handlers but skip configuration binding
        services.AddSingleton<IAuthorizationHandler, ScopeAuthorizationHandler>();
        services.AddSingleton<IAuthorizationHandler, AcrAuthorizationHandler>();
        services.AddSingleton<IAuthorizationHandler, UmaResourceAuthorizationHandler>();
        services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

        // Register default options
        services.Configure<SecurityLevelOptions>(opt => { });
        services.Configure<AcrRankingOptions>(opt => { });

        services.AddAuthorizationBuilder()
            .SetDefaultPolicy(new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .RequireClaim("acr")
                .Build())
            .AddPolicy(Policies.ElevatedAccess, policy =>
                policy.RequireAuthenticatedUser()
                    .AddRequirements(new AcrRequirement("acr3"))
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

    /// <summary>
    /// Registers application layer with configuration-driven options.
    /// Recommended for production use to enable appsettings-based security policies.
    /// </summary>
    public static IServiceCollection AddApplicationLayer(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Register authorization handlers
        services.AddSingleton<IAuthorizationHandler, ScopeAuthorizationHandler>();
        services.AddSingleton<IAuthorizationHandler, AcrAuthorizationHandler>();
        services.AddSingleton<IAuthorizationHandler, UmaResourceAuthorizationHandler>();
        services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

        // Bind configuration options from appsettings.json
        services.Configure<SecurityLevelOptions>(
            configuration.GetSection(SecurityLevelOptions.SectionName));
        services.Configure<AcrRankingOptions>(
            configuration.GetSection(AcrRankingOptions.SectionName));

        services.AddAuthorizationBuilder()
            .SetDefaultPolicy(new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .RequireClaim("acr")
                .Build())
            .AddPolicy(Policies.ElevatedAccess, policy =>
                policy.RequireAuthenticatedUser()
                    .AddRequirements(new AcrRequirement("acr3"))
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

