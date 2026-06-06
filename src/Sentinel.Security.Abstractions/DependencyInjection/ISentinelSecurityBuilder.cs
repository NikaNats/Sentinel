using Microsoft.Extensions.DependencyInjection;

namespace Sentinel.Security.Abstractions.DependencyInjection;

/// <summary>
///     Contract for composing Sentinel security modules through DI extensions.
/// </summary>
public interface ISentinelSecurityBuilder
{
    IServiceCollection Services { get; }
}
