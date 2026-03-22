using Microsoft.Extensions.DependencyInjection;
using Sentinel.AspNetCore.Middleware;
using Sentinel.Middleware.Filters;

namespace Sentinel.AspNetCore.Extensions;

/// <summary>
/// Dependency injection extensions for Sentinel ASP.NET Core integration.
/// Provides a fluent API for configuring DPoP validation, mTLS binding, and idempotency filters.
/// </summary>
public static class SentinelAspNetCoreExtensions
{
    /// <summary>
    /// Adds Sentinel ASP.NET Core middleware and filters to the service collection.
    /// </summary>
    /// <param name="services">Service collection.</param>
    /// <returns>Builder for fluent configuration.</returns>
    public static SentinelAspNetCoreBuilder AddSentinelAspNetCore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services, nameof(services));
        return new SentinelAspNetCoreBuilder(services);
    }
}

/// <summary>
/// Builder for configuring Sentinel ASP.NET Core features.
/// </summary>
public sealed class SentinelAspNetCoreBuilder
{
    private readonly IServiceCollection _services;
    private bool _dpopValidationAdded;
    private bool _idempotencyFiltersAdded;
    private bool _mtlsBindingAdded;

    /// <summary>
    /// Initializes a new instance of <see cref="SentinelAspNetCoreBuilder"/>.
    /// </summary>
    /// <param name="services">Service collection.</param>
    public SentinelAspNetCoreBuilder(IServiceCollection services)
    {
        _services = services;
    }

    /// <summary>
    /// Adds RFC 9449 DPoP (Demonstration of Proof-of-Possession) validation middleware.
    /// </summary>
    /// <returns>This builder for method chaining.</returns>
    public SentinelAspNetCoreBuilder AddDPoPValidation()
    {
        if (_dpopValidationAdded)
        {
            return this;
        }

        _ = _services.AddScoped<DpopValidationMiddleware>();
        _dpopValidationAdded = true;

        return this;
    }

    /// <summary>
    /// Adds idempotency enforcement via Idempotency-Key header with Redis-backed state storage.
    /// </summary>
    /// <returns>This builder for method chaining.</returns>
    public SentinelAspNetCoreBuilder AddIdempotencyFilters()
    {
        if (_idempotencyFiltersAdded)
        {
            return this;
        }

        _ = _services.AddScoped<RequireIdempotencyAttribute>();
        _idempotencyFiltersAdded = true;

        return this;
    }

    /// <summary>
    /// Adds mTLS (mutual TLS) certificate binding validation.
    /// Validates certificate thumbprint (x5t or x5t#S256) matches claimed identity.
    /// </summary>
    /// <returns>This builder for method chaining.</returns>
    public SentinelAspNetCoreBuilder AddMtlsBinding()
    {
        if (_mtlsBindingAdded)
        {
            return this;
        }

        _ = _services.AddScoped<MtlsBindingMiddleware>();
        _ = _services.AddScoped<RequireMtlsBindingAttribute>();
        _mtlsBindingAdded = true;

        return this;
    }

    /// <summary>
    /// Adds all Sentinel ASP.NET Core features (DPoP validation, mTLS binding, idempotency).
    /// </summary>
    /// <returns>This builder for method chaining.</returns>
    public SentinelAspNetCoreBuilder AddAll()
    {
        return AddDPoPValidation()
            .AddMtlsBinding()
            .AddIdempotencyFilters();
    }
}
