using System.Net;
using System.Reflection;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Redis;
using StackExchange.Redis;
using Xunit;

namespace Sentinel.Tests.Unit.Unit;

public sealed class RedisConnectionProviderTests
{
    [Fact(DisplayName = "✅ Unit: Comma-separated endpoints are correctly parsed into ConfigurationOptions")]
    public void Constructor_WithMultipleEndpoints_ParsesCorrectly()
    {
        // Arrange
        var options = new RedisOptions
        {
            EndPoint = "redis-node-1:6379,redis-node-2:6380,redis-node-3:6381",
            SyncTimeout = 5000
        };

        // Act
        var provider = new RedisConnectionProvider(options, NullLogger<RedisConnectionProvider>.Instance);

        var optionsField = typeof(RedisConnectionProvider)
            .GetField("_options", BindingFlags.NonPublic | BindingFlags.Instance);

        var parsedOptions = (ConfigurationOptions)optionsField!.GetValue(provider)!;

        // Assert
        parsedOptions.EndPoints.Should().HaveCount(3);

        var ep1 = parsedOptions.EndPoints[0] as DnsEndPoint;
        ep1.Should().NotBeNull("Endpoint should be parsed as DnsEndPoint");
        ep1!.Host.Should().Be("redis-node-1");
        ep1.Port.Should().Be(6379);

        var ep2 = parsedOptions.EndPoints[1] as DnsEndPoint;
        ep2.Should().NotBeNull();
        ep2!.Host.Should().Be("redis-node-2");
        ep2.Port.Should().Be(6380);

        var ep3 = parsedOptions.EndPoints[2] as DnsEndPoint;
        ep3.Should().NotBeNull();
        ep3!.Host.Should().Be("redis-node-3");
        ep3.Port.Should().Be(6381);
    }

    [Fact(DisplayName = "✅ Unit: ClientName, Keep-Alive, and ChannelPrefix are securely configured")]
    public void Constructor_ConfiguresSecurityAndAuditingInvariants()
    {
        // Arrange
        var options = new RedisOptions { EndPoint = "localhost:6379" };

        // Act
        var provider = new RedisConnectionProvider(options, NullLogger<RedisConnectionProvider>.Instance);

        var optionsField = typeof(RedisConnectionProvider)
            .GetField("_options", BindingFlags.NonPublic | BindingFlags.Instance);

        var parsedOptions = (ConfigurationOptions)optionsField!.GetValue(provider)!;

        // Assert
        parsedOptions.ClientName.Should().Be("Sentinel_Security_Gateway_Node");
        parsedOptions.KeepAlive.Should().Be(60);
        parsedOptions.ChannelPrefix.Should().Be("sentinel");
    }

    [Fact(DisplayName = "✅ Unit: Timeout invariants are correctly mapped from RedisOptions")]
    public void Constructor_MapsTimeoutsCorrectly()
    {
        // Arrange
        var options = new RedisOptions { EndPoint = "localhost:6379", SyncTimeout = 4500 };

        // Act
        var provider = new RedisConnectionProvider(options, NullLogger<RedisConnectionProvider>.Instance);

        var optionsField = typeof(RedisConnectionProvider)
            .GetField("_options", BindingFlags.NonPublic | BindingFlags.Instance);

        var parsedOptions = (ConfigurationOptions)optionsField!.GetValue(provider)!;

        // Assert
        parsedOptions.ConnectTimeout.Should().Be(4500);
        parsedOptions.SyncTimeout.Should().Be(4500);
        parsedOptions.AsyncTimeout.Should().Be(4500);
    }
}
