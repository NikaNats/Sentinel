using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Moq;
using Sentinel.Infrastructure.Cryptography;

namespace Sentinel.Tests.Unit.Unit;

public sealed class AesGcmEncryptionServiceTests
{
    private static string GenerateRandomKeyBase64()
    {
        var keyBytes = new byte[32];
        RandomNumberGenerator.Fill(keyBytes);
        return Convert.ToBase64String(keyBytes);
    }

    private static IOptionsMonitor<CryptographyOptions> CreateOptionsMonitor(CryptographyOptions value)
    {
        var mock = new Mock<IOptionsMonitor<CryptographyOptions>>();
        mock.Setup(m => m.CurrentValue).Returns(value);
        return mock.Object;
    }

    private static byte[] EncryptLegacyRaw(string plainText, byte[] keyBytes)
    {
        using var aes = new AesGcm(keyBytes, 16);

        Span<byte> iv = stackalloc byte[12];
        RandomNumberGenerator.Fill(iv);

        var plaintextBytes = Encoding.UTF8.GetBytes(plainText);
        var ciphertext = new byte[plaintextBytes.Length];
        Span<byte> tag = stackalloc byte[16];

        aes.Encrypt(iv, plaintextBytes, ciphertext, tag);

        var result = new byte[iv.Length + tag.Length + ciphertext.Length];
        iv.CopyTo(result.AsSpan(0, 12));
        tag.CopyTo(result.AsSpan(12, 16));
        Buffer.BlockCopy(ciphertext, 0, result, 28, ciphertext.Length);

        return result;
    }

    [Fact(DisplayName = "✅ Crypto: Encrypt and Decrypt successfully round-trips using the active key")]
    public void EncryptAndDecrypt_SuccessfulRoundTrip()
    {
        var activeKey = GenerateRandomKeyBase64();
        var options = CreateOptionsMonitor(new CryptographyOptions
        {
            ActiveKeyId = "2026-key-v1",
            KeyRing = new Dictionary<string, string> { ["2026-key-v1"] = activeKey }
        });

        var sut = new AesGcmEncryptionService(options);
        const string plainText = "sentinel-high-assurance-pii-data";

        var ciphertext = sut.Encrypt(plainText);
        var decrypted = sut.Decrypt(ciphertext);

        decrypted.Should().Be(plainText);
    }

    [Fact(DisplayName = "🔄 NIST SP 800-57: Rotating active key preserves decryption of historical ciphertexts")]
    public void KeyRotation_DecryptsHistoricalCiphertexts()
    {
        var keyA = GenerateRandomKeyBase64();
        var options1 = CreateOptionsMonitor(new CryptographyOptions
        {
            ActiveKeyId = "key-a",
            KeyRing = new Dictionary<string, string> { ["key-a"] = keyA }
        });

        var sut1 = new AesGcmEncryptionService(options1);
        const string originalText = "confidential-v1-record";
        var ciphertextA = sut1.Encrypt(originalText);

        var keyB = GenerateRandomKeyBase64();
        var options2 = CreateOptionsMonitor(new CryptographyOptions
        {
            ActiveKeyId = "key-b",
            KeyRing = new Dictionary<string, string>
            {
                ["key-a"] = keyA,
                ["key-b"] = keyB
            }
        });

        var sut2 = new AesGcmEncryptionService(options2);

        var decryptedA = sut2.Decrypt(ciphertextA);

        var newCiphertext = sut2.Encrypt("new-data");

        decryptedA.Should().Be(originalText, "Rotated key ring must preserve historical decryption.");

        var act = () => sut1.Decrypt(newCiphertext);
        act.Should().Throw<Exception>("First generation service cannot decrypt data encrypted with the rotated key.");
    }

    [Fact(DisplayName =
        "🛡️ Integrity: Tampering with a single bit of ciphertext must fail-closed via AEAD authentication")]
    public void Decrypt_WithTamperedCiphertext_ThrowsCryptographicException()
    {
        var activeKey = GenerateRandomKeyBase64();
        var options = CreateOptionsMonitor(new CryptographyOptions
        {
            ActiveKeyId = "key-1",
            KeyRing = new Dictionary<string, string> { ["key-1"] = activeKey }
        });

        var sut = new AesGcmEncryptionService(options);
        var ciphertext = sut.Encrypt("sensitive-payload-bytes");

        ciphertext[ciphertext.Length / 2] ^= 0x01;

        var act = () => sut.Decrypt(ciphertext);
        act.Should()
            .Throw<CryptographicException>("AES-GCM AEAD authentication tag validation must fail closed on tampering.");
    }

    [Fact(DisplayName = "✓ Legacy: Verifies unversioned legacy ciphertext fallback decryption")]
    public void Decrypt_WithLegacyCiphertext_SuccessfullyFallsBackToLegacyKey()
    {
        var legacyKeyBase64 = GenerateRandomKeyBase64();
        var legacyKeyBytes = Convert.FromBase64String(legacyKeyBase64);
        const string plainText = "legacy-database-record-from-2024";

        var legacyCiphertext = EncryptLegacyRaw(plainText, legacyKeyBytes);

        var activeKey = GenerateRandomKeyBase64();
        var modernOptions = CreateOptionsMonitor(new CryptographyOptions
        {
            ActiveKeyId = "modern-key-v1",
            KeyRing = new Dictionary<string, string> { ["modern-key-v1"] = activeKey },
            LegacyMasterKey = legacyKeyBase64
        });

        var modernSut = new AesGcmEncryptionService(modernOptions);

        var decrypted = modernSut.Decrypt(legacyCiphertext);

        decrypted.Should().Be(plainText,
            "Modern service must transparently fall back to legacy key for unversioned ciphertexts.");
    }
}
