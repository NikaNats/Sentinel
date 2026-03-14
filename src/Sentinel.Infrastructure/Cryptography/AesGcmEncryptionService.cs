using Sentinel.Application.Common.Abstractions;
using System.Security.Cryptography;
using System.Text;

namespace Sentinel.Infrastructure.Cryptography;

public sealed class AesGcmEncryptionService(IConfiguration configuration) : IEncryptionService
{
    private readonly byte[] key = GetMasterKey(configuration);

    public byte[] Encrypt(string plainText)
    {
        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);

        var cipherBytes = new byte[plainBytes.Length];
        var tag = new byte[16];

        using var aesGcm = new AesGcm(key, tag.Length);
        aesGcm.Encrypt(nonce, plainBytes, cipherBytes, tag);

        var result = new byte[nonce.Length + tag.Length + cipherBytes.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(tag, 0, result, nonce.Length, tag.Length);
        Buffer.BlockCopy(cipherBytes, 0, result, nonce.Length + tag.Length, cipherBytes.Length);

        return result;
    }

    public string Decrypt(byte[] cipherData)
    {
        if (cipherData.Length < 28)
        {
            throw new CryptographicException("Ciphertext payload is too short.");
        }

        var nonce = new byte[12];
        var tag = new byte[16];
        var cipherBytes = new byte[cipherData.Length - nonce.Length - tag.Length];

        Buffer.BlockCopy(cipherData, 0, nonce, 0, nonce.Length);
        Buffer.BlockCopy(cipherData, nonce.Length, tag, 0, tag.Length);
        Buffer.BlockCopy(cipherData, nonce.Length + tag.Length, cipherBytes, 0, cipherBytes.Length);

        var plainBytes = new byte[cipherBytes.Length];

        using var aesGcm = new AesGcm(key, tag.Length);
        aesGcm.Decrypt(nonce, cipherBytes, tag, plainBytes);

        return Encoding.UTF8.GetString(plainBytes);
    }

    private static byte[] GetMasterKey(IConfiguration configuration)
    {
        var encoded = configuration["Cryptography:MasterKey"];
        if (string.IsNullOrWhiteSpace(encoded))
        {
            throw new InvalidOperationException("Cryptography:MasterKey is required and must be a base64-encoded 32-byte key.");
        }

        var decoded = Convert.FromBase64String(encoded);
        if (decoded.Length != 32)
        {
            throw new InvalidOperationException("Cryptography:MasterKey must decode to exactly 32 bytes for AES-256-GCM.");
        }

        return decoded;
    }
}
