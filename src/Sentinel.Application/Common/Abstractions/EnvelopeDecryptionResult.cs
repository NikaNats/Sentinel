namespace Sentinel.Application.Common.Abstractions;

/// <summary>
///     Result of an envelope decryption that also reports whether the
///     ciphertext was produced under a non-active key (rotation grace) or the
///     legacy unversioned format, and carries the lazily re-wrapped ciphertext
///     encrypted under the current active key.
/// </summary>
/// <param name="PlainText">The decrypted plaintext.</param>
/// <param name="RequiresRewrap">
///     True when the envelope key differs from the active key (or the payload
///     was unversioned legacy), so the caller SHOULD persist
///     <paramref name="RewrappedCipher" /> to converge storage on the active key.
/// </param>
/// <param name="RewrappedCipher">
///     Re-encryption of <paramref name="PlainText" /> under the active key,
///     or null when <paramref name="RequiresRewrap" /> is false.
/// </param>
public sealed record EnvelopeDecryptionResult(
    string PlainText,
    bool RequiresRewrap,
    byte[]? RewrappedCipher);
