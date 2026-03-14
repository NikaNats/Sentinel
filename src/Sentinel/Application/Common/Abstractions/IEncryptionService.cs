namespace Sentinel.Application.Common.Abstractions;

public interface IEncryptionService
{
    byte[] Encrypt(string plainText);
    string Decrypt(byte[] cipherData);
}
