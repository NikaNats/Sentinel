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
///     security resilience validation suite.
///     Enforces Fail-Fast principle by blocking unsafe fallback mechanisms (e.g., InMemory stores)
///     in production, staging, and UAT environments to prevent security downgrades.
/// </summary>
public sealed class FailFastResilienceTests
{
    [Theory(DisplayName =
        "🔴 Fail-Fast 1: Registering InMemoryIdempotencyStore in non-development environments blocks startup")]
    [InlineData("Staging")]
    [InlineData("Production")]
    [InlineData("UAT")]
    public async Task StartupFilter_WhenInMemoryStoreInNonDevelopment_MustThrowInvalidOperationException(
        string environmentName)
    {
        var services = new ServiceCollection();

        var envMock = new Mock<IWebHostEnvironment>();
        envMock.SetupGet(x => x.EnvironmentName).Returns(environmentName);
        services.AddSingleton(envMock.Object);
        services.AddSingleton<IHostEnvironment>(envMock.Object);
        services.AddLogging();

        services.AddSingleton<IIdempotencyStore, InMemoryIdempotencyStore>();
        services.AddSingleton<IStartupFilter, SecurityInvariantsStartupFilter>();

        var act = async () =>
        {
            await using var provider = services.BuildServiceProvider();
            var filter = provider.GetRequiredService<IStartupFilter>();
            var appBuilderMock = new Mock<IApplicationBuilder>();
            var action = filter.Configure(_ => { });
            action(appBuilderMock.Object);
        };

        await act.Should().ThrowAsync<InvalidOperationException>()
            .Where(ex => ex.Message.Contains("CRITICAL SECURITY INVARIANT VIOLATED")
                         && ex.Message.Contains("InMemoryIdempotencyStore")
                         && ex.Message.Contains("non-development environment"));
    }

    [Theory(DisplayName = "🔴 Fail-Fast 2: Missing Redis endpoint in non-development environments blocks startup")]
    [InlineData("Staging")]
    [InlineData("Production")]
    public async Task StartupFilter_WhenRedisEndpointMissingInNonDevelopment_MustThrowInvalidOperationException(
        string environmentName)
    {
        var services = new ServiceCollection();

        var envMock = new Mock<IWebHostEnvironment>();
        envMock.SetupGet(x => x.EnvironmentName).Returns(environmentName);
        services.AddSingleton(envMock.Object);
        services.AddSingleton<IHostEnvironment>(envMock.Object);
        services.AddLogging();

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["KeyPrefix"] = "sentinel_test:"
            })
            .Build();

        services.AddRedisSecurityCaches(config);
        services.AddSingleton<IStartupFilter, SecurityInvariantsStartupFilter>();

        var act = async () =>
        {
            await using var provider = services.BuildServiceProvider();
            var filter = provider.GetRequiredService<IStartupFilter>();
            var appBuilderMock = new Mock<IApplicationBuilder>();
            var action = filter.Configure(_ => { });
            action(appBuilderMock.Object);
        };

        await act.Should().ThrowAsync<InvalidOperationException>()
            .Where(ex => ex.Message.Contains("Redis Connection EndPoint must be configured."));
    }

    [Fact(DisplayName = "✓ Sandbox: Strict Redis registration is allowed in development environment")]
    public async Task StartupFilter_WithStrictRedisRegistrationInDevelopmentEnvironment_DoesNotThrow()
    {
        var services = new ServiceCollection();

        var envMock = new Mock<IWebHostEnvironment>();
        envMock.SetupGet(x => x.EnvironmentName).Returns(Environments.Development);
        services.AddSingleton(envMock.Object);
        services.AddSingleton<IHostEnvironment>(envMock.Object);
        services.AddLogging();

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["EndPoint"] = "localhost:6379",
                ["KeyPrefix"] = "sentinel_test:"
            })
            .Build();

        services.AddRedisSecurityCaches(config);
        services.AddSingleton<IStartupFilter, SecurityInvariantsStartupFilter>();

        var act = async () =>
        {
            await using var provider = services.BuildServiceProvider();
            var filter = provider.GetRequiredService<IStartupFilter>();
            var appBuilderMock = new Mock<IApplicationBuilder>();
            var action = filter.Configure(_ => { });
            action(appBuilderMock.Object);
        };

        await act.Should().NotThrowAsync();
    }
}
