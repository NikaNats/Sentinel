using Microsoft.Extensions.Configuration;
using Sentinel.Infrastructure.Cryptography;
using System.Security.Cryptography;

namespace Sentinel.Tests.Unit;

public sealed class AesGcmEncryptionServiceTests
{
    [Fact]
    public void EncryptDecrypt_RoundTrip_ReturnsOriginalPlaintext()
    {
        var sut = new AesGcmEncryptionService(BuildConfig());
        const string plainText = "pii-value-123";

        var encrypted = sut.Encrypt(plainText);
        var decrypted = sut.Decrypt(encrypted);

        Assert.Equal(plainText, decrypted);
    }

    [Fact]
    public void Decrypt_WhenCipherTampered_ThrowsCryptographicException()
    {
        var sut = new AesGcmEncryptionService(BuildConfig());
        var encrypted = sut.Encrypt("top-secret");

        encrypted[^1] ^= 0xFF;

        Assert.ThrowsAny<CryptographicException>(() => sut.Decrypt(encrypted));
    }

    private static IConfiguration BuildConfig()
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Cryptography:MasterKey"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            })
            .Build();
    }
}
