using System.Net;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Sentinel.Security.Diagnostics;

namespace Sentinel.Tests.Unit.Unit;

public sealed class SecurityContextHasherTests
{
    private static void ConfigureServices(HttpContext context)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPrivacyKeyManager>(new FakePrivacyKeyManager(new byte[32]));
        services.AddSingleton<IPrivacyPreservingHasher, PrivacyPreservingHasher>();
        context.RequestServices = services.BuildServiceProvider();
    }

    private sealed class FakePrivacyKeyManager(byte[] pepper) : IPrivacyKeyManager
    {
        public ReadOnlySpan<byte> GetMasterPepper() => pepper;
    }

    [Fact(DisplayName =
        "⚡ Performance guarantee: IP hashing does not allocate a single byte on the heap (0 Bytes Allocated)")]
    public void HashIp_ZeroAllocations_EnforcesHeapHygiene()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("2001:db8:85a3:8d3:1319:8a2e:370:7348");
        ConfigureServices(context);

        // First run to cover JIT compilation overhead (Warm-up)
        _ = SecurityContextHasher.HashIp(context);

        // Act: Measure bytes allocated on the heap for the current thread
        var startBytes = GC.GetAllocatedBytesForCurrentThread();
        _ = SecurityContextHasher.HashIp(context);
        var endBytes = GC.GetAllocatedBytesForCurrentThread();

        var allocatedBytes = endBytes - startBytes;

        // Assert: Mathematically, exactly 0 bytes must be allocated
        allocatedBytes.Should().Be(0,
            "IP address hashing on the cryptographic hot-path must not cause memory allocations to avoid GC pressure.");
    }

    [Theory(DisplayName = "🔍 Validity: Various IP formats successfully generate a Hex hash")]
    [InlineData("127.0.0.1", "IPv4 Loopback")]
    [InlineData("::1", "IPv6 Loopback")]
    [InlineData("192.168.1.100", "IPv4 Private")]
    [InlineData("2001:db8::1", "IPv6 Global")]
    public void HashIp_WithVariousIpFormats_GeneratesValidHex(string ipAddress, string scenario)
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(ipAddress);
        ConfigureServices(context);

        // Act
        var hash = SecurityContextHasher.HashIp(context);

        // Assert
        hash.Should().NotBeNullOrWhiteSpace(scenario);
        hash.Should().NotBe("unknown");
        hash.Length.Should().Be(64, "HMAC-SHA256 Hex output must always be exactly 64 characters long");

        // Must contain only valid Hex characters
        hash.Should().MatchRegex("^[0-9A-F]{64}$", scenario);
    }
}
