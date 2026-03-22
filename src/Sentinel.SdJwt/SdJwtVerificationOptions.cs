namespace Sentinel.SdJwt;

/// <summary>
/// Configuration options for Selective Disclosure JWT (SD-JWT) verification and presentation handling.
/// Implements RFC 9901 selective disclosure and key binding support.
/// </summary>
public sealed class SdJwtVerificationOptions
{
    /// <summary>
    /// Gets or sets the maximum age in seconds for key binding tokens.
    /// Helping prevent replay of old key binding proofs.
    /// Default: 60 seconds (1 minute).
    /// </summary>
    public int KeyBindingMaxAgeSeconds { get; init; } = 60;

    /// <summary>
    /// Gets or sets a value indicating whether key binding nonce validation is required.
    /// When enabled, the key binding JWT must contain a matching nonce claim.
    /// Default: false.
    /// </summary>
    public bool RequireKeyBindingNonce { get; init; }

    /// <summary>
    /// Gets or sets the allowed clock skew in seconds for key binding token iat validation.
    /// Helps accommodate minor time synchronization differences between systems.
    /// Default: 0 seconds (strict validation).
    /// </summary>
    public int AllowedClockSkewSeconds { get; init; }

    /// <summary>
    /// Gets or sets the allowed disclosure hash algorithms.
    /// By default, only "sha-256" is supported per RFC 9901.
    /// </summary>
    public string[] AllowedDisclosureHashAlgorithms { get; init; } = ["sha-256"];
}
