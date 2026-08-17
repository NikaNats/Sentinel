using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sentinel.AspNetCore.Infrastructure;
using Sentinel.AspNetCore.Middleware;
using Sentinel.AspNetCore.Options;
using Sentinel.AspNetCore.Stores;
using Sentinel.Security.Abstractions.Idempotency;
using Sentinel.Security.Abstractions.Options;

namespace Sentinel.AspNetCore.Extensions;

public static class SentinelAspNetCoreExtensions
{
    public static SentinelAspNetCoreBuilder AddSentinelAspNetCore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddMemoryCache();

        // G4: production guardrails are now enforced, not merely documented.
        // Blocks InMemoryIdempotencyStore and EF-backed nonce+JTI stores outside Development.
        // TryAddEnumerable keeps registration idempotent when AddSentinelAspNetCore is called twice.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupFilter, SecurityInvariantsStartupFilter>());

        services.Configure<JsonOptions>(options =>
        {
            options.SerializerOptions.TypeInfoResolverChain.Insert(0, AspNetCoreJsonContext.Default);
        });
        services.Configure<Microsoft.AspNetCore.Mvc.JsonOptions>(options =>
        {
            options.JsonSerializerOptions.TypeInfoResolverChain.Insert(0, AspNetCoreJsonContext.Default);
        });

        return new SentinelAspNetCoreBuilder(services);
    }

    public static IApplicationBuilder UseSentinelSecurityPipeline(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        app.UseMiddleware<SecurityHeadersMiddleware>();
        app.UseMiddleware<CorrelationIdMiddleware>();
        app.UseMiddleware<DpopValidationMiddleware>();
        app.UseMiddleware<MtlsBindingMiddleware>();
        app.UseMiddleware<AcrValidationMiddleware>();

        return app;
    }

    /// <summary>
    ///     Registers the security middlewares that MUST run before authentication:
    ///     security headers, correlation id propagation (activity baggage), and DPoP
    ///     proof validation. Placing these before <c>UseAuthentication()</c> ensures the
    ///     correlation id baggage is attached before token validation and security events
    ///     (e.g. TOKEN_REPLAY_ALERT) are emitted.
    /// </summary>
    public static IApplicationBuilder UseSentinelPreAuthenticationSecurity(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        app.UseMiddleware<SecurityHeadersMiddleware>();
        app.UseMiddleware<CorrelationIdMiddleware>();
        app.UseMiddleware<DpopValidationMiddleware>();

        return app;
    }

    /// <summary>
    ///     Registers the security middlewares that depend on an authenticated principal
    ///     and MUST run after <c>UseAuthentication()</c>: mTLS certificate binding
    ///     (RFC 8705 cnf claim) and ACR step-up validation.
    /// </summary>
    public static IApplicationBuilder UseSentinelPostAuthenticationSecurity(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        app.UseMiddleware<MtlsBindingMiddleware>();
        app.UseMiddleware<AcrValidationMiddleware>();

        return app;
    }
}

public sealed class SentinelAspNetCoreBuilder(IServiceCollection services)
{
    private static readonly HashSet<string> GloballyAllowedAlgorithms = new(StringComparer.OrdinalIgnoreCase)
    {
        "PS256", "ES256", "EdDSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
    };

    private int _dpopValidationAdded;
    private int _idempotencyFiltersAdded;
    private int _mtlsBindingAdded;

    public SentinelAspNetCoreBuilder AddDPoPValidation()
    {
        if (Interlocked.Exchange(ref _dpopValidationAdded, 1) == 1)
        {
            return this;
        }

        services.AddOptions<DPoPOptions>()
            .BindConfiguration(DPoPOptions.SectionName)
            .PostConfigure(options =>
                options.AllowedAlgorithms = options.AllowedAlgorithms?
                    .Distinct(StringComparer.Ordinal)
                    .ToArray() ?? [])
            .Validate(options =>
                {
                    if (options.AllowedAlgorithms == null || options.AllowedAlgorithms.Length == 0)
                    {
                        return false;
                    }

                    return options.AllowedAlgorithms.All(alg => GloballyAllowedAlgorithms.Contains(alg));
                },
                "CRITICAL SECURITY INVARIANT VIOLATED: Configured DPoP algorithms must be restricted only to secure FAPI 2.0 Baseline/Advanced or FIPS 204 PQC profiles (PS256, ES256, EdDSA, ML-DSA). Weak algorithms (RS256, HS256, none) are strictly prohibited.")
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddSingleton(TimeProvider.System);
        services.AddSingleton(sp =>
        {
            var timeProvider = sp.GetRequiredService<TimeProvider>();
            return new L1AntiFloodCache(timeProvider, TimeSpan.FromSeconds(3));
        });

        return this;
    }

    public SentinelAspNetCoreBuilder AddIdempotencyFilters()
    {
        if (Interlocked.Exchange(ref _idempotencyFiltersAdded, 1) == 1)
        {
            return this;
        }

        services.TryAddSingleton<IIdempotencyStore, InMemoryIdempotencyStore>();

        return this;
    }

    public SentinelAspNetCoreBuilder AddMtlsBinding()
    {
        if (Interlocked.Exchange(ref _mtlsBindingAdded, 1) == 1)
        {
            return this;
        }

        services.AddOptions<MtlsBindingOptions>()
            .BindConfiguration(MtlsBindingOptions.SectionName);

        services.AddSingleton<MtlsCertificateCache>();

        return this;
    }

    public SentinelAspNetCoreBuilder AddAll() =>
        AddDPoPValidation()
            .AddMtlsBinding()
            .AddIdempotencyFilters();

    public SentinelAspNetCoreBuilder ConfigureAcrRanking(Action<AcrRankingOptions>? configure = null)
    {
        if (configure is not null)
        {
            _ = services.Configure(configure);
        }
        else
        {
            _ = services.AddOptions<AcrRankingOptions>()
                .BindConfiguration(AcrRankingOptions.SectionName)
                .ValidateDataAnnotations()
                .ValidateOnStart();
        }

        _ = services.AddSingleton<IAuthorizationMiddlewareResultHandler, StepUpAuthorizationResultHandler>();

        return this;
    }
}
