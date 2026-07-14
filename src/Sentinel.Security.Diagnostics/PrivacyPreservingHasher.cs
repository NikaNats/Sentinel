using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Sentinel.Security.Diagnostics;

/// <summary>
///     Defines a privacy-preserving IP address hasher.
/// </summary>
public interface IPrivacyPreservingHasher
{
    string HashIpAddress(IPAddress ipAddress);

    /// <summary>
    ///     Hashes a sensitive string (JTI, Session ID, User ID) using an ephemeral daily derived key.
    ///     Used to prevent PII and persistent identifier leaks in logs/telemetry.
    /// </summary>
    string Hash(string value);
}

/// <summary>
///     Performs zero-allocation daily-keyed HMAC-SHA256 IP address hashing.
/// </summary>
public sealed class PrivacyPreservingHasher : IPrivacyPreservingHasher
{
    private readonly IPrivacyKeyManager _keyManager;
    private readonly TimeProvider _timeProvider;

    // For safe, fast sharing between threads, we use a volatile reference
    private volatile DailyKeyCache _dailyKeyCache = new(0, new byte[32]);

    /// <summary>
    ///     Initializes a new instance of the <see cref="PrivacyPreservingHasher" /> class.
    /// </summary>
    public PrivacyPreservingHasher(IPrivacyKeyManager keyManager, TimeProvider? timeProvider = null)
    {
        _keyManager = keyManager ?? throw new ArgumentNullException(nameof(keyManager));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public string HashIpAddress(IPAddress ipAddress)
    {
        ArgumentNullException.ThrowIfNull(ipAddress);

        var now = _timeProvider.GetUtcNow();
        var dateKey = now.Year * 10000 + now.Month * 100 + now.Day; // e.g., 20260329

        // 1. Get or generate today's ephemeral key
        var cache = _dailyKeyCache;
        if (cache.DateKey != dateKey)
        {
            cache = DeriveDailyKey(dateKey, now.ToString("yyyyMMdd"));
        }

        // 2. Write IP bytes onto the stack (IPv4 = 4b, IPv6 = 16b)
        Span<byte> ipBytes = stackalloc byte[16];
        if (!ipAddress.TryWriteBytes(ipBytes, out var bytesWritten))
        {
            return "UNKNOWN_IP_FORMAT";
        }

        // 3. Allocate memory for the hash on the stack
        Span<byte> hashBytes = stackalloc byte[32];

        // FIPS 140-3 compliant instantaneous hashing (Zero-Allocation)
        HMACSHA256.HashData(cache.DerivedKey, ipBytes.Slice(0, bytesWritten), hashBytes);

        return ConvertToHexValue(hashBytes);
    }

    public string Hash(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var now = _timeProvider.GetUtcNow();
        var dateKey = now.Year * 10000 + now.Month * 100 + now.Day;

        var cache = _dailyKeyCache;
        if (cache.DateKey != dateKey)
        {
            cache = DeriveDailyKey(dateKey, now.ToString("yyyyMMdd"));
        }

        var valueBytes = Encoding.UTF8.GetBytes(value);
        Span<byte> hashBytes = stackalloc byte[32];

        HMACSHA256.HashData(cache.DerivedKey, valueBytes, hashBytes);

        return ConvertToHexValue(hashBytes);
    }

    private DailyKeyCache DeriveDailyKey(int dateKey, string dateString)
    {
        var masterPepper = _keyManager.GetMasterPepper();
        if (masterPepper.Length != 32)
        {
            return _dailyKeyCache;
        }

        Span<byte> dateBytes = stackalloc byte[8];
        var dateBytesWritten = Encoding.UTF8.GetBytes(dateString, dateBytes);

        var newDerivedKey = new byte[32];
        HMACSHA256.HashData(masterPepper, dateBytes.Slice(0, dateBytesWritten), newDerivedKey);

        var newCache = new DailyKeyCache(dateKey, newDerivedKey);
        _dailyKeyCache = newCache; // Atomic update

        return newCache;
    }

    private static string ConvertToHexValue(ReadOnlySpan<byte> hashBytes)
    {
        // 0-Allocation String creation
        var state = new HashState
        {
            Part1 = BitConverter.ToUInt64(hashBytes.Slice(0, 8)),
            Part2 = BitConverter.ToUInt64(hashBytes.Slice(8, 8)),
            Part3 = BitConverter.ToUInt64(hashBytes.Slice(16, 8)),
            Part4 = BitConverter.ToUInt64(hashBytes.Slice(24, 8))
        };

        return string.Create(64, state, static (span, s) =>
        {
            Span<byte> buffer = stackalloc byte[32];
            BitConverter.TryWriteBytes(buffer.Slice(0, 8), s.Part1);
            BitConverter.TryWriteBytes(buffer.Slice(8, 8), s.Part2);
            BitConverter.TryWriteBytes(buffer.Slice(16, 8), s.Part3);
            BitConverter.TryWriteBytes(buffer.Slice(24, 8), s.Part4);

            for (var i = 0; i < 32; i++)
            {
                var val = buffer[i];
                span[i * 2] = GetHexChar(val >> 4);
                span[i * 2 + 1] = GetHexChar(val & 0x0F);
            }
        });
    }

    private static char GetHexChar(int value) => value < 10 ? (char)('0' + value) : (char)('A' + (value - 10));

    private sealed record DailyKeyCache(int DateKey, byte[] DerivedKey);

    private struct HashState
    {
        public ulong Part1;
        public ulong Part2;
        public ulong Part3;
        public ulong Part4;
    }
}
