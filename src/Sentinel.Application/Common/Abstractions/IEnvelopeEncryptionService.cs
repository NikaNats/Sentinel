namespace Sentinel.Application.Common.Abstractions;

/// <summary>
///     Envelope-cryptography variant of <see cref="IEncryptionService" /> that
///     exposes key lifecycle information after decryption.
///     NIST SP 800-57: ciphertexts MUST be re-encrypted under the current
///     active key once the producing key is retired from the keyring.
/// </summary>
public interface IEnvelopeEncryptionService : IEncryptionService
{
    /// <summary>
    ///     Decrypts a versioned (or legacy unversioned) ciphertext envelope and
    ///     reports whether the payload was produced under a non-active key.
    ///     When <see cref="EnvelopeDecryptionResult.RequiresRewrap" /> is true,
    ///     the caller should persist <see cref="EnvelopeDecryptionResult.RewrappedCipher" />
    ///     so that data converges on the active key (lazy re-wrap).
    /// </summary>
    EnvelopeDecryptionResult DecryptEnvelope(byte[] cipherData);
}
