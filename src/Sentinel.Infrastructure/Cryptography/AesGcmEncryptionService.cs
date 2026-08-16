using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Security.Diagnostics;

namespace Sentinel.Infrastructure.Cryptography;

/// <summary>
///     NIST SP 800-57 compliant AES-256-GCM encryption service with envelope cryptography.
///     Implements versioned ciphertext envelopes allowing:
///     - Seamless multi-key support (key rotation without re-encryption)
///     - Zero-downtime key rotation (dynamic configuration reload via IOptionsMonitor)
///     - Backward compatibility with legacy unversioned ciphertexts
///     - Zero-allocation Span&lt;T&gt; parsing for header metadata
///     - FedRAMP High compliance via auditable key version information
/// </summary>
internal sealed class AesGcmEncryptionService : IEnvelopeEncryptionService, IDisposable
{
    private const byte MagicByte = 0x56;
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly IDisposable? _optionsChangeListener;

    private volatile CryptoState _state;

    public AesGcmEncryptionService(IOptionsMonitor<CryptographyOptions> optionsMonitor)
    {
        ArgumentNullException.ThrowIfNull(optionsMonitor);

        _state = BuildState(optionsMonitor.CurrentValue);

        _optionsChangeListener = optionsMonitor.OnChange(newOptions =>
        {
            try
            {
                _state = BuildState(newOptions);
            }
#pragma warning disable CA1031
            catch (Exception)
            {
            }
#pragma warning restore CA1031
        });
    }

    public void Dispose() => _optionsChangeListener?.Dispose();

    public byte[] Encrypt(string plainText)
    {
        var state = _state;

        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var keyIdBytes = Encoding.UTF8.GetBytes(state.ActiveKeyId);

        if (keyIdBytes.Length > 255)
        {
            throw new InvalidOperationException(
                $"ActiveKeyId '{state.ActiveKeyId}' exceeds 255 bytes when UTF-8 encoded.");
        }

        Span<byte> nonce = stackalloc byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        Span<byte> tag = stackalloc byte[TagSize];

        var cipherBytes = new byte[plainBytes.Length];

        // Modern .NET 8+ zero-allocation API: AesGcm(key.AsSpan())
        using (var aesGcm = new AesGcm(state.ActiveKey.AsSpan(), TagSize))
        {
            aesGcm.Encrypt(nonce, plainBytes, cipherBytes, tag);
        }

        var envelopeSize = 1 + 1 + keyIdBytes.Length + NonceSize + TagSize + cipherBytes.Length;
        var result = new byte[envelopeSize];

        var cursor = 0;
        result[cursor++] = MagicByte;
        result[cursor++] = (byte)keyIdBytes.Length;

        Buffer.BlockCopy(keyIdBytes, 0, result, cursor, keyIdBytes.Length);
        cursor += keyIdBytes.Length;

        nonce.CopyTo(result.AsSpan(cursor, NonceSize));
        cursor += NonceSize;

        tag.CopyTo(result.AsSpan(cursor, TagSize));
        cursor += TagSize;

        Buffer.BlockCopy(cipherBytes, 0, result, cursor, cipherBytes.Length);

        return result;
    }

    public string Decrypt(byte[] cipherData)
    {
        if (cipherData.Length < NonceSize + TagSize + 2)
        {
            throw new CryptographicException("Ciphertext payload is too short.");
        }

        var state = _state;

        if (cipherData[0] == MagicByte && cipherData.Length > 2 &&
            TryDecryptVersioned(cipherData, state, out _, out var plainText))
        {
            return plainText;
        }

        if (state.LegacyKey != null)
        {
            return DecryptLegacy(cipherData, state.LegacyKey);
        }

        throw new CryptographicException(
            "Unable to decrypt: Payload format is unversioned (V0) but no LegacyMasterKey is configured.");
    }

    public EnvelopeDecryptionResult DecryptEnvelope(byte[] cipherData)
    {
        if (cipherData.Length < NonceSize + TagSize + 2)
        {
            throw new CryptographicException("Ciphertext payload is too short.");
        }

        var state = _state;

        if (cipherData[0] == MagicByte && cipherData.Length > 2 &&
            TryDecryptVersioned(cipherData, state, out var keyId, out var plainText))
        {
            if (string.Equals(keyId, state.ActiveKeyId, StringComparison.Ordinal))
            {
                return new EnvelopeDecryptionResult(plainText, RequiresRewrap: false, RewrappedCipher: null);
            }

            // NIST SP 800-57 rotation grace: the payload was produced under a
            // key that is no longer active. Re-wrap lazily and hand the caller
            // the ciphertext to persist, converging storage on the active key.
            var rewrapped = Encrypt(plainText);

            var tags = new TagList { { "key_id", keyId } };
            AuthTelemetry.LazyRewraps.Add(1, tags);
            AuthTelemetry.KeyRingActiveKeyMismatches.Add(1, tags);

            return new EnvelopeDecryptionResult(plainText, RequiresRewrap: true, rewrapped);
        }

        if (state.LegacyKey != null)
        {
            var plainLegacy = DecryptLegacy(cipherData, state.LegacyKey);
            var rewrapped = Encrypt(plainLegacy);

            var legacyTags = new TagList { { "key_id", "legacy-v0" } };
            AuthTelemetry.LazyRewraps.Add(1, legacyTags);
            AuthTelemetry.KeyRingActiveKeyMismatches.Add(1, legacyTags);

            return new EnvelopeDecryptionResult(plainLegacy, RequiresRewrap: true, rewrapped);
        }

        throw new CryptographicException(
            "Unable to decrypt: Payload format is unversioned (V0) but no LegacyMasterKey is configured.");
    }

    private static CryptoState BuildState(CryptographyOptions config)
    {
        if (string.IsNullOrWhiteSpace(config.ActiveKeyId) || !config.KeyRing.ContainsKey(config.ActiveKeyId))
        {
            throw new InvalidOperationException(
                "Cryptography:ActiveKeyId is missing or not found in KeyRing. Verify configuration.");
        }

        var keyRing = new Dictionary<string, byte[]>(StringComparer.Ordinal);

        foreach (var (keyId, base64Key) in config.KeyRing)
        {
            var keyBytes = Convert.FromBase64String(base64Key);
            if (keyBytes.Length != 32)
            {
                throw new InvalidOperationException(
                    $"Key '{keyId}' must be exactly 32 bytes for AES-256. Got {keyBytes.Length}.");
            }

            keyRing[keyId] = keyBytes;
        }

        var activeKey = keyRing[config.ActiveKeyId];

        byte[]? legacyKey = null;
        if (!string.IsNullOrWhiteSpace(config.LegacyMasterKey))
        {
            legacyKey = Convert.FromBase64String(config.LegacyMasterKey);
            if (legacyKey.Length != 32)
            {
                throw new InvalidOperationException(
                    $"LegacyMasterKey must be exactly 32 bytes for AES-256. Got {legacyKey.Length}.");
            }
        }

        return new CryptoState(config.ActiveKeyId, activeKey, keyRing, legacyKey);
    }

    private static bool TryDecryptVersioned(
        ReadOnlySpan<byte> payload,
        CryptoState state,
        out string keyId,
        out string plainText)
    {
        keyId = string.Empty;
        plainText = string.Empty;

        try
        {
            var cursor = 1;
            var keyIdLen = payload[cursor++];

            if (payload.Length < cursor + keyIdLen + NonceSize + TagSize)
            {
                return false;
            }

            var keyIdBytes = payload.Slice(cursor, keyIdLen);
            cursor += keyIdLen;

            keyId = Encoding.UTF8.GetString(keyIdBytes);
            if (!state.KeyRing.TryGetValue(keyId, out var key))
            {
                return false;
            }

            var nonce = payload.Slice(cursor, NonceSize);
            cursor += NonceSize;

            var tag = payload.Slice(cursor, TagSize);
            cursor += TagSize;

            var cipherBytes = payload.Slice(cursor);
            var plainBytes = new byte[cipherBytes.Length];

            using var aesGcm = new AesGcm(key.AsSpan(), TagSize);
            aesGcm.Decrypt(nonce, cipherBytes, tag, plainBytes);

            plainText = Encoding.UTF8.GetString(plainBytes);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static string DecryptLegacy(ReadOnlySpan<byte> payload, byte[] legacyKey)
    {
        var nonce = payload.Slice(0, NonceSize);
        var tag = payload.Slice(NonceSize, TagSize);
        var cipherBytes = payload.Slice(NonceSize + TagSize);
        var plainBytes = new byte[cipherBytes.Length];

        using var aesGcm = new AesGcm(legacyKey.AsSpan(), TagSize);
        aesGcm.Decrypt(nonce, cipherBytes, tag, plainBytes);

        return Encoding.UTF8.GetString(plainBytes);
    }

    private sealed record CryptoState(
        string ActiveKeyId,
        byte[] ActiveKey,
        Dictionary<string, byte[]> KeyRing,
        byte[]? LegacyKey);
}
