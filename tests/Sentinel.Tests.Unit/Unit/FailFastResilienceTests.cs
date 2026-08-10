using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Moq;
using Sentinel.AspNetCore.Extensions;
using Sentinel.AspNetCore.Infrastructure;
using Sentinel.AspNetCore.Stores;
using Sentinel.Redis.Extensions;
using Sentinel.Security.Abstractions.Idempotency;
using Xunit;

namespace Sentinel.Tests.Unit.Unit;

/// <summary>
///     Security resilience validation suite.
///     Enforces the Fail-Fast principle by blocking unsafe fallback mechanisms (e.g., InMemory stores)
///     in production, staging, and UAT environments to prevent security downgrades.
/// </summary>
public sealed class FailFastResilienceTests
{
    private static ServiceCollection CreateBaseServices(string environmentName)
    {
        var services = new ServiceCollection();

        var envMock = new Mock<IWebHostEnvironment>();
        envMock.SetupGet(x => x.EnvironmentName).Returns(environmentName);

        services.AddSingleton(envMock.Object);
        services.AddSingleton<IHostEnvironment>(envMock.Object);
        services.AddLogging();

        return services;
    }

    private static void ApplyStartupFilter(IServiceProvider provider)
    {
        var filter = provider.GetRequiredService<IStartupFilter>();
        var appBuilder = Mock.Of<IApplicationBuilder>();
        var configureAction = filter.Configure(_ => { });
        configureAction(appBuilder);
    }

    [Theory(DisplayName = "🔴 Fail-Fast 1: Registering InMemoryIdempotencyStore in non-development environments blocks startup")]
    [InlineData("Staging")]
    [InlineData("Production")]
    [InlineData("UAT")]
    public async Task StartupFilter_WhenInMemoryStoreInNonDevelopment_MustThrowInvalidOperationException(string environmentName)
    {
        var services = CreateBaseServices(environmentName);
        services.AddSingleton<IIdempotencyStore, InMemoryIdempotencyStore>();
        services.AddSingleton<IStartupFilter, SecurityInvariantsStartupFilter>();

        var act = async () =>
        {
            await using var provider = services.BuildServiceProvider();
            ApplyStartupFilter(provider);
        };

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*CRITICAL SECURITY INVARIANT VIOLATED*InMemoryIdempotencyStore*non-development environment*");
    }

    [Theory(DisplayName = "🔴 Fail-Fast 2: Missing Redis endpoint in non-development environments blocks startup")]
    [InlineData("Staging")]
    [InlineData("Production")]
    public async Task StartupFilter_WhenRedisEndpointMissingInNonDevelopment_MustThrowInvalidOperationException(string environmentName)
    {
        var services = CreateBaseServices(environmentName);

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["KeyPrefix"] = "sentinel_test:"
            })
            .Build();

        services.AddSingleton<IConfiguration>(config);
        services.AddRedisSecurityCaches(config);
        services.AddSingleton<IStartupFilter, SecurityInvariantsStartupFilter>();

        var act = async () =>
        {
            await using var provider = services.BuildServiceProvider();
            ApplyStartupFilter(provider);
        };

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*Redis Connection EndPoint must be configured.*");
    }

    [Fact(DisplayName = "✓ Sandbox: Strict Redis registration is allowed in development environment")]
    public async Task StartupFilter_WithStrictRedisRegistrationInDevelopmentEnvironment_DoesNotThrow()
    {
        var services = CreateBaseServices(Environments.Development);

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["EndPoint"] = "localhost:6379",
                ["KeyPrefix"] = "sentinel_test:"
            })
            .Build();

        services.AddSingleton<IConfiguration>(config);
        services.AddRedisSecurityCaches(config);
        services.AddSingleton<IStartupFilter, SecurityInvariantsStartupFilter>();

        var act = async () =>
        {
            await using var provider = services.BuildServiceProvider();
            ApplyStartupFilter(provider);
        };

        await act.Should().NotThrowAsync();
    }

    [Fact(DisplayName = "✓ Registration: AddSentinelAspNetCore wires the SecurityInvariantsStartupFilter into the host")]
    public void AddSentinelAspNetCore_RegistersSecurityInvariantsStartupFilter()
    {
        var services = CreateBaseServices(Environments.Development);
        services.AddSentinelAspNetCore();

        // Correctly dispose the ServiceProvider to prevent test runner memory leaks
        using var provider = services.BuildServiceProvider();
        var filters = provider.GetServices<IStartupFilter>();

        filters.Should().ContainSingle(f => f.GetType().Name == nameof(SecurityInvariantsStartupFilter));
    }
}
