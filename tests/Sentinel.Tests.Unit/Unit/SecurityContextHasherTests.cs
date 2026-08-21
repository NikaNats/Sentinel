using System;
using System.Net;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Security.Diagnostics;

namespace Sentinel.Tests.Unit.Unit;

/// <summary>
///     High-assurance unit tests for SecurityContextHasher.
///     Verifies zero-allocation request-scoped caching, hash generation,
///     and null-safe graceful degradation without leaking ServiceProvider instances.
/// </summary>
public sealed class SecurityContextHasherTests : IDisposable
{
    private static readonly byte[] StaticMasterPepper =
    [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    ];

    private readonly ServiceProvider _serviceProvider;

    public SecurityContextHasherTests()
    {
        // Allocate and build the DI container ONCE per test class instance.
        // Building a ServiceProvider per invocation and never disposing it leaks
        // orphaned containers (and their reflection caches) into Gen2 under
        // Stryker/xUnit mass runs - CA2000/CA2213 hygiene requires disposal.
        var services = new ServiceCollection();
        services.AddSingleton<IPrivacyKeyManager>(new FakePrivacyKeyManager(StaticMasterPepper));
        services.AddSingleton<IPrivacyPreservingHasher, PrivacyPreservingHasher>();
        _serviceProvider = services.BuildServiceProvider();
    }

    public void Dispose()
    {
        _serviceProvider.Dispose();
    }

    private void AttachServices(HttpContext context)
    {
        context.RequestServices = _serviceProvider;
    }

    [Fact(DisplayName =
        "⚡ Performance guarantee: IP hashing cache-hit does not allocate a single byte on the heap (0 Bytes Allocated)")]
    public void HashIp_ZeroAllocations_EnforcesHeapHygiene()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("2001:db8:85a3:8d3:1319:8a2e:370:7348");
        AttachServices(context);

        // First run computes and caches the hash in HttpContext.Items (Warm-up)
        var initialHash = SecurityContextHasher.HashIp(context);
        initialHash.Should().NotBeNullOrWhiteSpace();

        // Act: Measure bytes allocated on the heap for the cached lookup
        var startBytes = GC.GetAllocatedBytesForCurrentThread();
        var cachedHash = SecurityContextHasher.HashIp(context);
        var endBytes = GC.GetAllocatedBytesForCurrentThread();

        var allocatedBytes = endBytes - startBytes;

        // Assert: Subsequent calls within the same HttpContext must allocate exactly 0 bytes
        allocatedBytes.Should().Be(0,
            "Subsequent IP address hash lookups on the same HttpContext must return the cached string reference with 0 allocations.");
        cachedHash.Should().BeSameAs(initialHash, "Cached lookup must return the exact same string instance.");
    }

    [Theory(DisplayName = "🔍 Validity: Various IP formats successfully generate a 64-hex SHA-256 HMAC hash")]
    [InlineData("127.0.0.1", "IPv4 Loopback")]
    [InlineData("::1", "IPv6 Loopback")]
    [InlineData("192.168.1.100", "IPv4 Private")]
    [InlineData("2001:db8::1", "IPv6 Global")]
    public void HashIp_WithVariousIpFormats_GeneratesValidHex(string ipAddress, string scenario)
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(ipAddress);
        AttachServices(context);

        // Act
        var hash = SecurityContextHasher.HashIp(context);

        // Assert
        hash.Should().NotBeNullOrWhiteSpace(scenario);
        hash.Should().NotBe("unknown");
        hash.Length.Should().Be(64, "HMAC-SHA256 Hex output must always be exactly 64 characters long.");
        hash.Should().MatchRegex("^[0-9A-F]{64}$", scenario);
    }

    [Fact(DisplayName =
        "🛡️ Null Safety: Missing HttpContext, RemoteIpAddress, or RequestServices falls back to 'unknown'")]
    public void HashIp_WithMissingContextOrIp_ReturnsUnknownSafely()
    {
        // 1. Null HttpContext
        SecurityContextHasher.HashIp(null!).Should().Be("unknown");

        // 2. HttpContext without RemoteIpAddress
        var contextWithoutIp = new DefaultHttpContext();
        AttachServices(contextWithoutIp);
        SecurityContextHasher.HashIp(contextWithoutIp).Should().Be("unknown");

        // 3. HttpContext without RequestServices
        var contextWithoutServices = new DefaultHttpContext
        {
            Connection = { RemoteIpAddress = IPAddress.Loopback }
        };
        SecurityContextHasher.HashIp(contextWithoutServices).Should().Be("unknown");
    }

    private sealed class FakePrivacyKeyManager(byte[] pepper) : IPrivacyKeyManager
    {
        private readonly byte[] _pepper = pepper ?? throw new ArgumentNullException(nameof(pepper));

        public ReadOnlySpan<byte> GetMasterPepper() => _pepper;
    }
}
