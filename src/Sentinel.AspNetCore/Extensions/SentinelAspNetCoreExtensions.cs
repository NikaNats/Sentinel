using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
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
}

public sealed class SentinelAspNetCoreBuilder
{
    private readonly IServiceCollection _services;
    private int _dpopValidationAdded;
    private int _idempotencyFiltersAdded;
    private int _mtlsBindingAdded;

    public SentinelAspNetCoreBuilder(IServiceCollection services)
    {
        _services = services;
    }

    public SentinelAspNetCoreBuilder AddDPoPValidation()
    {
        if (Interlocked.Exchange(ref _dpopValidationAdded, 1) == 1)
        {
            return this;
        }

        _services.AddOptions<DPoPOptions>()
            .BindConfiguration(DPoPOptions.SectionName)
            .ValidateDataAnnotations();

        _services.AddSingleton(TimeProvider.System);
        _services.AddSingleton(sp =>
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

        _services.TryAddSingleton<IIdempotencyStore, InMemoryIdempotencyStore>();

        return this;
    }

    public SentinelAspNetCoreBuilder AddMtlsBinding()
    {
        if (Interlocked.Exchange(ref _mtlsBindingAdded, 1) == 1)
        {
            return this;
        }

        _services.AddOptions<MtlsBindingOptions>()
            .BindConfiguration(MtlsBindingOptions.SectionName);

        _services.AddSingleton<MtlsCertificateCache>();

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
            _ = _services.Configure(configure);
        }
        else
        {
            _ = _services.AddOptions<AcrRankingOptions>()
                .BindConfiguration(AcrRankingOptions.SectionName)
                .ValidateDataAnnotations()
                .ValidateOnStart();
        }

        _ = _services.AddSingleton<IAuthorizationMiddlewareResultHandler, StepUpAuthorizationResultHandler>();

        return this;
    }
}
