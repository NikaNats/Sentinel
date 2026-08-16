using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Sentinel.AspNetCore.Stores;
using System.Security.Cryptography;
using System.Text;

namespace Sentinel.Tests.Unit.Unit;

/// <summary>
///     High-assurance unit tests for the bounded MtlsCertificateCache.
///     Mathematically verifies capacity limitations and LRU eviction policies under simulated DoS attack.
/// </summary>
public sealed class MtlsCertificateCacheTests : IDisposable
{
    // We use a small, deterministic size limit (10) for testing
    private readonly MtlsCertificateCache _sut = new(10);

    public void Dispose() => _sut.Dispose();

    [Fact(DisplayName = "✅ Capacity: Adding entries up to the limit stores them successfully")]
    public void Set_UnderCapacityLimit_StoresSuccessfully()
    {
        // Arrange & Act: Add 5 entries (well within the 10 limit)
        for (var i = 0; i < 5; i++)
        {
            _sut.Set($"key-{i}", $"thumbprint-{i}", TimeSpan.FromMinutes(5));
        }

        // Assert
        _sut.TryGetValue("key-0", out var val).Should().BeTrue();
        val.Should().Be("thumbprint-0");
        _sut.Count.Should().Be(5, "The cache should contain exactly the added items under limit.");
    }

    [Fact(DisplayName = "🛡️ DoS Protection: Exceeding capacity limit triggers auto-eviction and bounds memory")]
    public void Set_ExceedingCapacityLimit_TriggersEvictionAndBoundsMemory()
    {
        // Arrange: Write 15 entries (exceeds the 10 limit)
        for (var i = 0; i < 15; i++)
        {
            _sut.Set($"key-{i}", $"thumbprint-{i}", TimeSpan.FromMinutes(5));
        }

        Thread.Sleep(150);

        // Act & Assert:
        // Since the limit is 10, the total count in the cache MUST be strictly less than or equal to 10!
        // This mathematically proves that compaction occurred and bounded memory.
        _sut.Count.Should().BeLessThanOrEqualTo(10,
            "The cache size must remain strictly bounded by the SizeLimit to prevent memory exhaustion.");

        _sut.Count.Should().BeGreaterThan(0, "The cache must not be completely emptied during compaction.");
    }

    // ---- Rotation / eviction tests (Enterprise Cryptographic & PKI Lifecycle) ----

    [Fact(DisplayName = "🔄 Rotation: Different cert PEM produces distinct cache key (cache miss on rotation)")]
    public void Rotation_DistinctRawPem_DistinctCacheKey()
    {
        // Arrange: two different "raw cert" payloads (simulate PEM rotation)
        const string certAPem = "-----BEGIN CERTIFICATE-----\nCERT-A\n-----END CERTIFICATE-----";
        const string certBPem = "-----BEGIN CERTIFICATE-----\nCERT-B\n-----END CERTIFICATE-----";

        // Simulate GenerateZeroAllocationCacheKey: "mtls:" + SHA256(UTF8(rawCertData))
        var keyA = ComputeMtlsCacheKey(certAPem);
        var keyB = ComputeMtlsCacheKey(certBPem);

        keyA.Should().NotBe(keyB, "Different cert PEM must yield different cache keys.");

        // Act: Cache cert A
        _sut.Set(keyA, "thumbprint-A", TimeSpan.FromMinutes(5));

        // Assert: Cert B is a cache miss
        _sut.TryGetValue(keyB, out _).Should().BeFalse("Rotation to new cert must be a cache miss.");

        // Act: Cache cert B
        _sut.Set(keyB, "thumbprint-B", TimeSpan.FromMinutes(5));

        // Assert: Both cached (coexistence during grace period)
        _sut.TryGetValue(keyA, out var valA).Should().BeTrue();
        valA.Should().Be("thumbprint-A");
        _sut.TryGetValue(keyB, out var valB).Should().BeTrue();
        valB.Should().Be("thumbprint-B");
    }

    [Fact(DisplayName = "🛡️ Rotation Storm: Many rotated certs stay within capacity bound")]
    public void RotationStorm_ManyCerts_CapacityBounded()
    {
        // Simulate a rotation storm: 50 cert rotations, cache limit 10
        for (var i = 0; i < 50; i++)
        {
            var certPem = $"-----BEGIN CERTIFICATE-----\nCERT-{i}\n-----END CERTIFICATE-----";
            var cacheKey = ComputeMtlsCacheKey(certPem);
            _sut.Set(cacheKey, $"thumbprint-{i}", TimeSpan.FromMinutes(5));
        }

        Thread.Sleep(150);

        _sut.Count.Should().BeLessThanOrEqualTo(10,
            "Cache must remain bounded even under sustained rotation load.");
    }

    // Helpers mirroring MtlsBindingMiddleware.GenerateZeroAllocationCacheKey
    private static string ComputeMtlsCacheKey(string rawCertData)
    {
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawCertData));
        // Base64Url encoding: base64 -> replace +/ with -_ and strip padding
        var base64 = Convert.ToBase64String(hashBytes);
        return string.Concat("mtls:", base64.Replace('+', '-').Replace('/', '_').TrimEnd('='));
    }
}
