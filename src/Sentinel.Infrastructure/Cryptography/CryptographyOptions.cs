namespace Sentinel.Infrastructure.Cryptography;

/// <summary>
///     NIST SP 800-57 compliant key management configuration for envelope cryptography.
///     Supports multiple cryptographic keys (key ring) with explicit versioning, enabling:
///     - Seamless key rotation without re-encrypting entire databases
///     - Backward compatibility with legacy unversioned keys
///     - FedRAMP High compliance via auditable key version metadata
///     - Zero-downtime cryptographic algorithm upgrades
/// </summary>
public sealed class CryptographyOptions
{
    public const string SectionName = "Cryptography";

    /// <summary>
    ///     The ID of the key that should be used for all NEW encryption operations.
    ///     Must reference a key present in the KeyRing dictionary.
    ///     Example: "2026-03-rev1"
    /// </summary>
    public string ActiveKeyId { get; init; } = string.Empty;

    /// <summary>
    ///     A dictionary of all valid keys (historical and active).
    ///     Key: Unique Key ID (e.g., "2026-03-rev1", "2025-12-rev1")
    ///     Value: Base64-encoded 32-byte AES-256 key
    ///     Example configuration:
    ///     {
    ///     "2026-03-rev1": "base64EncodedKey32Bytes...",
    ///     "2025-12-rev1": "base64EncodedPreviousKey..."
    ///     }
    /// </summary>
    public Dictionary<string, string> KeyRing { get; init; } = new();

    /// <summary>
    ///     The legacy key used before versioning was introduced.
    ///     Required to prevent data loss for ciphertexts encrypted with the
    ///     previous unversioned AES-GCM implementation. Once all data has been
    ///     lazily re-encrypted with versioned keys, this can be safely removed.
    ///     Value: Base64-encoded 32-byte AES-256 key
    /// </summary>
    public string? LegacyMasterKey { get; init; }
}
