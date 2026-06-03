using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Moq;
using Sentinel.AspNetCore.Infrastructure;
using Sentinel.AspNetCore.Stores;
using Sentinel.Redis.Extensions;
using Sentinel.Security.Abstractions.Idempotency;

namespace Sentinel.Tests.Unit.Unit;

/// <summary>
///     Enterprise security resilience tests.
///     Verifies that unsafe fallbacks are not allowed in production (Fail-Fast).
/// </summary>
public sealed class FailFastResilienceTests
{
    [Fact(DisplayName = "🔴 Fail-Fast 1: Registering InMemoryIdempotencyStore in production blocks startup")]
    public void StartupFilter_WhenInMemoryStoreInProduction_MustThrowInvalidOperationException()
    {
        // Arrange
        var services = new ServiceCollection();

        var envMock = new Mock<IWebHostEnvironment>();
        envMock.SetupGet(x => x.EnvironmentName).Returns(Environments.Production);
        services.AddSingleton(envMock.Object);
        services.AddSingleton<IHostEnvironment>(envMock.Object);

        services.AddSingleton<IIdempotencyStore, InMemoryIdempotencyStore>();
        services.AddSingleton<IStartupFilter, SecurityInvariantsStartupFilter>();

        // Build and execute entirely inside act
        var act = () =>
        {
            using var provider = services.BuildServiceProvider();
            var filter = provider.GetRequiredService<IStartupFilter>();
            var appBuilderMock = new Mock<IApplicationBuilder>();
            var action = filter.Configure(_ => { });
            action(appBuilderMock.Object);
        };

        // Assert: system must block startup with critical error
        act.Should().Throw<Exception>()
            .Where(ex => ex.Message.Contains("CRITICAL SECURITY INVARIANT VIOLATED")
                         && ex.Message.Contains("InMemoryIdempotencyStore"));
    }

    [Fact(DisplayName = "🔴 Fail-Fast 2: EnableInMemoryFallback = true in production blocks startup")]
    public void StartupFilter_WhenRedisFallbackEnabledInProduction_MustThrowInvalidOperationException()
    {
        // Arrange
        var services = new ServiceCollection();

        var envMock = new Mock<IWebHostEnvironment>();
        envMock.SetupGet(x => x.EnvironmentName).Returns(Environments.Production);
        services.AddSingleton(envMock.Object);
        services.AddSingleton<IHostEnvironment>(envMock.Object);

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["EndPoint"] = "localhost:6379",
                ["EnableInMemoryFallback"] = "true"
            })
            .Build();

        services.AddRedisSecurityCaches(config);
        services.AddSingleton<IStartupFilter, SecurityInvariantsStartupFilter>();

        // Build inside act to capture options validation
        var act = () =>
        {
            using var provider = services.BuildServiceProvider();
            var filter = provider.GetRequiredService<IStartupFilter>();
            var appBuilderMock = new Mock<IApplicationBuilder>();
            var action = filter.Configure(_ => { });
            action(appBuilderMock.Object);
        };

        // Assert: startup must be blocked by options validator
        act.Should().Throw<Exception>()
            .Where(ex => ex.Message.Contains("CRITICAL SECURITY VIOLATION")
                         && ex.Message.Contains("EnableInMemoryFallback"));
    }

    [Fact(DisplayName = "✓ Sandbox: Unsafe fallbacks are allowed in development environment")]
    public void StartupFilter_InDevelopmentEnvironment_DoesNotThrow()
    {
        // Arrange
        var services = new ServiceCollection();

        var envMock = new Mock<IWebHostEnvironment>();
        envMock.SetupGet(x => x.EnvironmentName).Returns(Environments.Development);
        services.AddSingleton(envMock.Object);
        services.AddSingleton<IHostEnvironment>(envMock.Object);

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["EndPoint"] = "localhost:6379",
                ["EnableInMemoryFallback"] = "true"
            })
            .Build();

        services.AddRedisSecurityCaches(config);
        services.AddSingleton<IStartupFilter, SecurityInvariantsStartupFilter>();

        // Fixed
        var act = () =>
        {
            using var provider = services.BuildServiceProvider();
            var filter = provider.GetRequiredService<IStartupFilter>();
            var appBuilderMock = new Mock<IApplicationBuilder>();
            var action = filter.Configure(_ => { });
            action(appBuilderMock.Object);
        };

        // Act & Assert: application should start without issues in development
        act.Should().NotThrow();
    }
}
