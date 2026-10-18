using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sentinel.Application.Auth.Models;
using ApplicationRevocation = Sentinel.Application.Auth.Interfaces.IAuthRevocationService;
using ApplicationSessionBlacklist = Sentinel.Application.Common.Abstractions.ISessionBlacklistCache;
using ApplicationSsfProcessor = Sentinel.Application.Auth.Interfaces.ISsfEventProcessor;
using SecurityRevocation = Sentinel.Security.Abstractions.Security.IAuthRevocationService;
using SecuritySessionBlacklist = Sentinel.Security.Abstractions.Session.ISessionBlacklistCache;
using SecuritySsfProcessor = Sentinel.Security.Abstractions.SSF.ISsfEventProcessor;

namespace Sentinel.AspNetCore.Extensions;

/// <summary>
///     Bridges the framework-level <c>Sentinel.Security.Abstractions</c> ports to the endpoint-level
///     <c>Sentinel.Application</c> ports, so hosts do not hand-write these adapters.
/// </summary>
public static class SentinelHostBridgeExtensions
{
    /// <summary>
    ///     Registers the revocation, SSF-processor and session-blacklist bridges. Each registration uses
    ///     <c>TryAdd</c>, so a host-provided implementation always wins.
    /// </summary>
    /// <remarks>
    ///     Requires the Application-level <see cref="ApplicationRevocation" /> (e.g. from <c>AddKeycloak</c>),
    ///     the Security-level <see cref="SecuritySsfProcessor" /> (from <c>AddSsfProcessing</c>) and the
    ///     Security-level <see cref="SecuritySessionBlacklist" /> (from the Redis or EF Core stores).
    /// </remarks>
    public static IServiceCollection AddSentinelHostBridges(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<SecurityRevocation, FailClosedAuthRevocationBridge>();
        services.TryAddScoped<ApplicationSsfProcessor, SsfEventProcessorBridge>();
        services.TryAddSingleton<ApplicationSessionBlacklist, SessionBlacklistCacheBridge>();

        return services;
    }
}

/// <summary>
///     The Security-level contract has no success flag, so a revocation the identity provider reports as
///     failed is surfaced as an exception. Callers such as the SSF processor then fail closed and do not
///     acknowledge the event.
/// </summary>
internal sealed class FailClosedAuthRevocationBridge(ApplicationRevocation inner) : SecurityRevocation
{
    public async Task RevokeAllSessionsAsync(string subject, CancellationToken cancellationToken = default)
    {
        if (!await inner.RevokeAllSessionsAsync(subject, cancellationToken))
        {
            throw new InvalidOperationException("Identity provider reported that session revocation failed.");
        }
    }
}

internal sealed class SsfEventProcessorBridge(SecuritySsfProcessor inner) : ApplicationSsfProcessor
{
    public async Task<SsfProcessResult> ProcessAsync(string setToken, CancellationToken ct)
    {
        var result = await inner.ProcessAsync(setToken, ct);
        return result.IsSuccess
            ? SsfProcessResult.Success()
            : SsfProcessResult.Invalid(result.ErrorMessage ?? "SSF processing failed");
    }
}

internal sealed class SessionBlacklistCacheBridge(SecuritySessionBlacklist inner, TimeProvider timeProvider)
    : ApplicationSessionBlacklist
{
    public Task BlacklistSessionAsync(string sessionId, TimeSpan ttl, CancellationToken ct) =>
        inner.BlacklistSessionAsync(sessionId, timeProvider.GetUtcNow() + ttl, ct);

    public ValueTask<bool> IsSessionBlacklistedAsync(string sessionId, CancellationToken ct) =>
        new(inner.IsBlacklistedAsync(sessionId, ct));
}
