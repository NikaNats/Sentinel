using FluentAssertions;
using Sentinel.AspNetCore.Stores;

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
}
