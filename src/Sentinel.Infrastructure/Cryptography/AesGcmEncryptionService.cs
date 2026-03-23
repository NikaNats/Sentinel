using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Sentinel.Application.Common.Abstractions;

namespace Sentinel.Infrastructure.Cryptography;

/// <summary>
/// NIST SP 800-57 compliant AES-256-GCM encryption service with envelope cryptography.
///
/// Implements versioned ciphertext envelopes allowing:
/// - Seamless multi-key support (key rotation without re-encryption)
/// - Backward compatibility with legacy unversioned ciphertexts
/// - Zero-allocation Span&lt;T&gt; parsing for header metadata
/// - FedRAMP High compliance via auditable key version information
///
/// Ciphertext Format (V1):
/// [Magic: 0x56] [KeyID Len: 1B] [KeyID: VarN] [Nonce: 12B] [Tag: 16B] [Cipher: Var]
///
/// Legacy Format (V0 - fallback):
/// [Nonce: 12B] [Tag: 16B] [Cipher: Var]
/// </summary>
internal sealed class AesGcmEncryptionService : IEncryptionService
{
    private const byte MagicByte = 0x56; // 'V' for Versioned
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly string _activeKeyId;
    private readonly byte[] _activeKey;
    private readonly Dictionary<string, byte[]> _keyRing = new(StringComparer.Ordinal);
    private readonly byte[]? _legacyKey;

    public AesGcmEncryptionService(IOptions<CryptographyOptions> options)
    {
        var config = options.Value;

        if (string.IsNullOrWhiteSpace(config.ActiveKeyId) || !config.KeyRing.ContainsKey(config.ActiveKeyId))
        {
            throw new InvalidOperationException(
                "Cryptography:ActiveKeyId is missing or not found in KeyRing. Verify appsettings.json.");
        }

        _activeKeyId = config.ActiveKeyId;

        // Decode KeyRing (all historical and current keys)
        foreach (var (keyId, base64Key) in config.KeyRing)
        {
            var keyBytes = Convert.FromBase64String(base64Key);
            if (keyBytes.Length != 32)
            {
                throw new InvalidOperationException(
                    $"Key '{keyId}' must be exactly 32 bytes for AES-256. Got {keyBytes.Length}.");
            }
            _keyRing[keyId] = keyBytes;
        }

        _activeKey = _keyRing[_activeKeyId];

        // Decode Legacy Key (for backward compatibility with V0 format)
        if (!string.IsNullOrWhiteSpace(config.LegacyMasterKey))
        {
            _legacyKey = Convert.FromBase64String(config.LegacyMasterKey);
            if (_legacyKey.Length != 32)
            {
                throw new InvalidOperationException(
                    $"LegacyMasterKey must be exactly 32 bytes for AES-256. Got {_legacyKey.Length}.");
            }
        }
    }

    /// <summary>
    /// Encrypts plaintext using the currently active key, wrapping it in a versioned envelope.
    ///
    /// Produces V1 format with Key ID metadata allowing seamless decryption after key rotation.
    /// </summary>
    public byte[] Encrypt(string plainText)
    {
        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var keyIdBytes = Encoding.UTF8.GetBytes(_activeKeyId);

        if (keyIdBytes.Length > 255)
        {
            throw new InvalidOperationException($"ActiveKeyId '{_activeKeyId}' exceeds 255 bytes when UTF-8 encoded.");
        }

        // Generate cryptographically random nonce
        var nonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        var cipherBytes = new byte[plainBytes.Length];
        var tag = new byte[TagSize];

        // Perform AES-256-GCM encryption
        using var aesGcm = new AesGcm(_activeKey, TagSize);
        aesGcm.Encrypt(nonce, plainBytes, cipherBytes, tag);

        // Construct V1 Envelope
        // Format: [Magic: 1B] [KeyIdLen: 1B] [KeyId: VarN] [Nonce: 12B] [Tag: 16B] [Cipher: Var]
        var envelopeSize = 1 + 1 + keyIdBytes.Length + NonceSize + TagSize + cipherBytes.Length;
        var result = new byte[envelopeSize];

        int cursor = 0;
        result[cursor++] = MagicByte;
        result[cursor++] = (byte)keyIdBytes.Length;

        Buffer.BlockCopy(keyIdBytes, 0, result, cursor, keyIdBytes.Length);
        cursor += keyIdBytes.Length;

        Buffer.BlockCopy(nonce, 0, result, cursor, NonceSize);
        cursor += NonceSize;

        Buffer.BlockCopy(tag, 0, result, cursor, TagSize);
        cursor += TagSize;

        Buffer.BlockCopy(cipherBytes, 0, result, cursor, cipherBytes.Length);

        return result;
    }

    /// <summary>
    /// Decrypts ciphertext from either V1 (versioned) or V0 (legacy) format.
    ///
    /// Attempts V1 format first. If that fails with AEAD tag corruption (legitimate for legacy data),
    /// falls back to V0 format using the legacy key. This gracefully handles the 1/256 probability
    /// that a legacy payload randomly starts with 0x56.
    /// </summary>
    public string Decrypt(byte[] cipherData)
    {
        if (cipherData.Length < NonceSize + TagSize + 2) // Minimum V1: MagicByte + KeyIdLen
        {
            throw new CryptographicException("Ciphertext payload is too short.");
        }

        ReadOnlySpan<byte> payload = cipherData;

        // Attempt V1 (Versioned) Format
        if (payload[0] == MagicByte && payload.Length > 2)
        {
            try
            {
                return DecryptV1(payload);
            }
            catch (CryptographicException)
            {
                // In the rare case (1/256 probability) that a legacy payload
                // randomly starts with 0x56, the AEAD tag check will fail here.
                // Fall through to legacy decryption.
            }
        }

        // Fallback to V0 (Legacy) Format
        if (_legacyKey != null)
        {
            return DecryptLegacy(payload);
        }

        throw new CryptographicException(
            "Unable to decrypt: Payload format is unversioned (V0) but no LegacyMasterKey is configured.");
    }

    /// <summary>
    /// Decrypts V1 (versioned) format ciphertext.
    ///
    /// Parses the Key ID from the envelope header and uses the corresponding key
    /// from the key ring to decrypt. Allows seamless support for historical keys.
    /// </summary>
    private string DecryptV1(ReadOnlySpan<byte> payload)
    {
        int cursor = 1; // Skip MagicByte
        byte keyIdLen = payload[cursor++];

        if (payload.Length < cursor + keyIdLen + NonceSize + TagSize)
        {
            throw new CryptographicException("Malformed versioned ciphertext: insufficient header data.");
        }

        // Extract Key ID (zero-copy using Span<T> slicing)
        var keyIdBytes = payload.Slice(cursor, keyIdLen);
        cursor += keyIdLen;

        var keyId = Encoding.UTF8.GetString(keyIdBytes);
        if (!_keyRing.TryGetValue(keyId, out var key))
        {
            throw new CryptographicException(
                $"Key ID '{keyId}' not found in KeyRing. Cannot decrypt data encrypted with unknown key.");
        }

        // Extract Nonce, Tag, and Ciphertext
        var nonce = payload.Slice(cursor, NonceSize);
        cursor += NonceSize;

        var tag = payload.Slice(cursor, TagSize);
        cursor += TagSize;

        var cipherBytes = payload.Slice(cursor);
        var plainBytes = new byte[cipherBytes.Length];

        // Perform AES-256-GCM decryption
        using var aesGcm = new AesGcm(key, TagSize);
        aesGcm.Decrypt(nonce, cipherBytes, tag, plainBytes);

        return Encoding.UTF8.GetString(plainBytes);
    }

    /// <summary>
    /// Decrypts V0 (legacy unversioned) format ciphertext.
    ///
    /// Used for data encrypted before key versioning was introduced.
    /// Format: [Nonce: 12B] [Tag: 16B] [Cipher: Var]
    /// </summary>
    private string DecryptLegacy(ReadOnlySpan<byte> payload)
    {
        var nonce = payload.Slice(0, NonceSize);
        var tag = payload.Slice(NonceSize, TagSize);
        var cipherBytes = payload.Slice(NonceSize + TagSize);
        var plainBytes = new byte[cipherBytes.Length];

        // Perform AES-256-GCM decryption with legacy key
        using var aesGcm = new AesGcm(_legacyKey!, TagSize);
        aesGcm.Decrypt(nonce, cipherBytes, tag, plainBytes);

        return Encoding.UTF8.GetString(plainBytes);
    }
}
