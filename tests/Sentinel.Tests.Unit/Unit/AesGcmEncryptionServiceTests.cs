using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Sentinel.Infrastructure.Cryptography;

namespace Sentinel.Tests.Unit;

public sealed class AesGcmEncryptionServiceTests
{
    /// <summary>
    /// V1 Envelope format: [Magic 0x56] [KeyIdLen] [KeyId...] [Nonce] [Tag] [Cipher]
    /// Verifies round-trip encryption with versioned key ring.
    /// </summary>
    [Fact]
    public void EncryptDecrypt_RoundTrip_V1Envelope_ReturnsOriginalPlaintext()
    {
        var sut = new AesGcmEncryptionService(BuildCryptographyOptions());
        const string plainText = "pii-value-123";

        var encrypted = sut.Encrypt(plainText);
        var decrypted = sut.Decrypt(encrypted);

        Assert.Equal(plainText, decrypted);
    }

    /// <summary>
    /// Verifies that V1 ciphertext includes Magic Byte (0x56) for versioning.
    /// </summary>
    [Fact]
    public void Encrypt_ProducesVersionedEnvelope_WithMagicByte()
    {
        var sut = new AesGcmEncryptionService(BuildCryptographyOptions());

        var encrypted = sut.Encrypt("test");

        Assert.Equal(0x56, encrypted[0]); // Magic Byte
    }

    /// <summary>
    /// Verifies AEAD authentication: tampering with ciphertext fails decryption.
    /// </summary>
    [Fact]
    public void Decrypt_WhenCipherTampered_ThrowsCryptographicException()
    {
        var sut = new AesGcmEncryptionService(BuildCryptographyOptions());
        var encrypted = sut.Encrypt("top-secret");

        // Corrupt the ciphertext portion (skip envelope header and tag)
        encrypted[^1] ^= 0xFF;

        Assert.ThrowsAny<CryptographicException>(() => sut.Decrypt(encrypted));
    }

    /// <summary>
    /// Verifies backward compatibility: V0 (legacy) format still decrypts
    /// when LegacyMasterKey is configured.
    /// </summary>
    [Fact]
    public void Decrypt_LegacyV0Format_WithLegacyKey_ReturnsOriginalPlaintext()
    {
        var sut = new AesGcmEncryptionService(BuildCryptographyOptionsWithLegacy());

        // Manually construct a V0 payload (Nonce + Tag + Cipher)
        // This simulates data encrypted with the old unversioned implementation
        const string expected = "legacy-data";
        var plainBytes = Encoding.UTF8.GetBytes(expected);

        var nonce = new byte[12];
        var tag = new byte[16];
        var cipherBytes = new byte[plainBytes.Length];

        using var aesGcm = new AesGcm(Convert.FromBase64String("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="), 16);
        aesGcm.Encrypt(nonce, plainBytes, cipherBytes, tag);

        // Construct legacy V0 envelope
        var legacyPayload = new byte[nonce.Length + tag.Length + cipherBytes.Length];
        Buffer.BlockCopy(nonce, 0, legacyPayload, 0, nonce.Length);
        Buffer.BlockCopy(tag, 0, legacyPayload, nonce.Length, tag.Length);
        Buffer.BlockCopy(cipherBytes, 0, legacyPayload, nonce.Length + tag.Length, cipherBytes.Length);

        var decrypted = sut.Decrypt(legacyPayload);

        Assert.Equal(expected, decrypted);
    }

    private static IOptions<CryptographyOptions> BuildCryptographyOptions()
    {
        var options = new CryptographyOptions
        {
            ActiveKeyId = "test-key-2026",
            KeyRing = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["test-key-2026"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            }
        };

        return Options.Create(options);
    }

    private static IOptions<CryptographyOptions> BuildCryptographyOptionsWithLegacy()
    {
        var options = new CryptographyOptions
        {
            ActiveKeyId = "test-key-2026",
            KeyRing = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["test-key-2026"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            },
            LegacyMasterKey = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
        };

        return Options.Create(options);
    }
}
