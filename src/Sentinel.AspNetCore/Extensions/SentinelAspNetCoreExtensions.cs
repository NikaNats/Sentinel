using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sentinel.AspNetCore.Middleware;
using Sentinel.AspNetCore.Options;
using Sentinel.AspNetCore.Stores;
using Sentinel.Security.Abstractions.Idempotency;
using Sentinel.Security.Abstractions.Options;

namespace Sentinel.AspNetCore.Extensions;

/// <summary>
///     Dependency injection extensions for Sentinel ASP.NET Core integration.
///     Provides a fluent API for configuring DPoP validation, mTLS binding, and idempotency filters.
/// </summary>
public static class SentinelAspNetCoreExtensions
{
    /// <summary>
    ///     Adds Sentinel ASP.NET Core middleware and filters to the service collection.
    /// </summary>
    /// <param name="services">Service collection.</param>
    /// <returns>Builder for fluent configuration.</returns>
    public static SentinelAspNetCoreBuilder AddSentinelAspNetCore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.Configure<Microsoft.AspNetCore.Http.Json.JsonOptions>(options =>
        {
            options.SerializerOptions.TypeInfoResolverChain.Insert(0, AspNetCoreJsonContext.Default);
        });
        services.Configure<Microsoft.AspNetCore.Mvc.JsonOptions>(options =>
        {
            options.JsonSerializerOptions.TypeInfoResolverChain.Insert(0, AspNetCoreJsonContext.Default);
        });

        return new SentinelAspNetCoreBuilder(services);
    }

    /// <summary>
    ///     Enforces the strict cryptographic and security pipeline ordering.
    ///     MUST be called before UseAuthentication and UseAuthorization.
    ///     This method ensures the following middleware order (non-negotiable):
    ///     1. SecurityHeadersMiddleware - Hardening headers (must be first to catch early rejections)
    ///     2. CorrelationIdMiddleware - Correlation and tracing context
    ///     3. DpopValidationMiddleware - Sender-constraining cryptographic validation (RFC 9449)
    ///     4. MtlsBindingMiddleware - Transport-layer identity binding
    ///     5. AcrValidationMiddleware - Authentication Context Class Reference enforcement
    /// </summary>
    /// <param name="app">Application builder.</param>
    /// <returns>Application builder for method chaining.</returns>
    public static IApplicationBuilder UseSentinelSecurityPipeline(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // 1. Hardening headers (must be first to catch early rejections)
        app.UseMiddleware<SecurityHeadersMiddleware>();

        // 2. Correlation and tracing context
        app.UseMiddleware<CorrelationIdMiddleware>();

        // 3. Sender-constraining cryptographic validation (RFC 9449)
        app.UseMiddleware<DpopValidationMiddleware>();

        // 4. Transport-layer identity binding
        app.UseMiddleware<MtlsBindingMiddleware>();

        // 5. Authentication Context Class Reference enforcement
        app.UseMiddleware<AcrValidationMiddleware>();

        return app;
    }
}

/// <summary>
///     Builder for configuring Sentinel ASP.NET Core features.
/// </summary>
public sealed class SentinelAspNetCoreBuilder
{
    private readonly IServiceCollection _services;
    private int _dpopValidationAdded;
    private int _idempotencyFiltersAdded;
    private int _mtlsBindingAdded;

    /// <summary>
    ///     Initializes a new instance of <see cref="SentinelAspNetCoreBuilder" />.
    /// </summary>
    /// <param name="services">Service collection.</param>
    public SentinelAspNetCoreBuilder(IServiceCollection services)
    {
        _services = services;
    }

    /// <summary>
    ///     Adds RFC 9449 DPoP (Demonstration of Proof-of-Possession) validation middleware.
    ///     Validates DPoP proof structure, signature, and nonce per specification.
    ///     Registers middleware dependencies in DI; the middleware itself is instantiated via UseMiddleware in the pipeline.
    /// </summary>
    /// <returns>This builder for method chaining.</returns>
    public SentinelAspNetCoreBuilder AddDPoPValidation()
    {
        // ✅ FIX: Thread-safe idempotent registration using Interlocked
        if (Interlocked.Exchange(ref _dpopValidationAdded, 1) == 1)
        {
            return this;
        }

        // Validate DPoP configuration via data annotations
        _ = _services.AddOptions<DPoPOptions>()
            .BindConfiguration(DPoPOptions.SectionName)
            .ValidateDataAnnotations();

        // NOTE: Do NOT register the middleware itself in DI (AddScoped<DpopValidationMiddleware>).
        // Middleware is instantiated by UseMiddleware<>() in the pipeline, not from DI.
        // Dependencies of the middleware will be resolved from DI when UseMiddleware() is called.

        return this;
    }

    /// <summary>
    ///     Adds idempotency enforcement via Idempotency-Key header with Redis-backed state storage.
    /// </summary>
    /// <returns>This builder for method chaining.</returns>
    public SentinelAspNetCoreBuilder AddIdempotencyFilters()
    {
        // ✅ FIX: Thread-safe idempotent registration using Interlocked
        if (Interlocked.Exchange(ref _idempotencyFiltersAdded, 1) == 1)
        {
            return this;
        }

        // Default to in-memory idempotency when no provider-specific implementation is registered.
        // Infrastructure packages (e.g., Sentinel.Redis) can override this registration.
        _services.TryAddSingleton<IIdempotencyStore, InMemoryIdempotencyStore>();

        // Do NOT register the old MVC RequireIdempotencyAttribute
        // The new IEndpointFilter IdempotencyFilter in Sentinel.AspNetCore.Filters is the single source of truth for Minimal APIs

        return this;
    }

    /// <summary>
    ///     Adds mTLS (mutual TLS) certificate binding validation.
    ///     Validates certificate thumbprint (x5t or x5t#S256) matches claimed identity.
    ///     Registers middleware dependencies in DI; the middleware itself is instantiated via UseMiddleware in the pipeline.
    /// </summary>
    /// <returns>This builder for method chaining.</returns>
    public SentinelAspNetCoreBuilder AddMtlsBinding()
    {
        if (Interlocked.Exchange(ref _mtlsBindingAdded, 1) == 1)
        {
            return this;
        }

        _services.AddOptions<MtlsBindingOptions>()
            .BindConfiguration(MtlsBindingOptions.SectionName);

        return this;
    }

    /// <summary>
    ///     Adds all Sentinel ASP.NET Core features (DPoP validation, mTLS binding, idempotency).
    /// </summary>
    /// <returns>This builder for method chaining.</returns>
    public SentinelAspNetCoreBuilder AddAll()
    {
        return AddDPoPValidation()
            .AddMtlsBinding()
            .AddIdempotencyFilters();
    }

    /// <summary>
    ///     Configures ACR (Authentication Context Class Reference) ranking options.
    ///     Defines the hierarchical mapping of ACR values for authorization decisions.
    /// </summary>
    /// <param name="configure">Configuration action for AcrRankingOptions.</param>
    /// <returns>This builder for method chaining.</returns>
    public SentinelAspNetCoreBuilder ConfigureAcrRanking(Action<AcrRankingOptions>? configure = null)
    {
        if (configure is not null)
        {
            _ = _services.Configure(configure);
        }
        else
        {
            // Bind from configuration section if present
            _ = _services.AddOptions<AcrRankingOptions>()
                .BindConfiguration(AcrRankingOptions.SectionName)
                .ValidateDataAnnotations()
                .ValidateOnStart();
        }

        // Register the step-up authorization result handler
        _ = _services.AddSingleton<IAuthorizationMiddlewareResultHandler, StepUpAuthorizationResultHandler>();

        return this;
    }
}
