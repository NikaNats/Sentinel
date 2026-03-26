namespace Sentinel.Domain.Auth;

/// <summary>
/// Cryptographically opaque handle for password reset requests.
/// Does NOT contain PII (email). The mapping exists server-side only.
/// Compliant with GDPR privacy-by-design and 2026 token best practices.
/// </summary>
public sealed record ResetToken
{
    /// <summary>
    /// High-entropy random handle (e.g., 32 bytes Base64Url encoded).
    /// This is the ONLY value sent to the user (no email/PII exposure).
    /// </summary>
    public required string TokenHandle { get; init; }

    /// <summary>
    /// UTC expiry time using DateTimeOffset for global temporal consistency.
    /// Must be validated against DateTimeOffset.UtcNow (zero-skew).
    /// </summary>
    public required DateTimeOffset ExpiresAtUtc { get; init; }

    /// <summary>
    /// Returns the opaque string to be sent to the user.
    /// Implementation Detail: This is a random handle, NOT a serialized PII string.
    /// </summary>
    public override string ToString() => TokenHandle;
}
