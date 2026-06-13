using System.Net;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using Sentinel.Security.Diagnostics;

namespace Sentinel.Benchmarks;

[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[RankColumn]
public class PrivacyPreservingHasherBenchmark : IDisposable
{
    private bool _disposed;
    private PrivacyPreservingHasher? _hasher;
    private IPAddress? _ipv4Address;
    private IPAddress? _ipv6Address;
    private IPrivacyKeyManager? _keyManager;

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            // Clean up resources if any are registered in future extensions
        }

        _disposed = true;
    }

    [GlobalSetup]
    public void GlobalSetup()
    {
        // Simulate Vault-sourced 256-bit entropy
        var pepper = new byte[32];
        RandomNumberGenerator.Fill(pepper);

        _keyManager = new FakePrivacyKeyManager(pepper);
        _hasher = new PrivacyPreservingHasher(_keyManager, TimeProvider.System);

        _ipv4Address = IPAddress.Parse("192.168.1.100");
        _ipv6Address = IPAddress.Parse("2001:db8:85a3:8d3:1319:8a2e:370:7348");
    }

    [Benchmark(Description = "Hash IPv4 Address (Zero-Allocation)")]
    public string HashIPv4() => _hasher!.HashIpAddress(_ipv4Address!);

    [Benchmark(Description = "Hash IPv6 Address (Zero-Allocation)")]
    public string HashIPv6() => _hasher!.HashIpAddress(_ipv6Address!);

    private sealed class FakePrivacyKeyManager(byte[] pepper) : IPrivacyKeyManager
    {
        public ReadOnlySpan<byte> GetMasterPepper() => pepper;
    }
}
