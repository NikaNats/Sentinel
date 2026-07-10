namespace Sentinel.Domain.Users;

/// <summary>
///     Privacy-hardened consent record for audit trail compliance.
///     Uses DateTimeOffset for global temporal consistency.
///     Stores IP as a secure cryptographic hash for GDPR compliance.
/// </summary>
public sealed record ConsentInfo
{
    /// <summary>
    ///     Indicates whether the user explicitly accepted the terms (domain invariant: must be true).
    /// </summary>
    public required bool TermsAccepted { get; init; }

    /// <summary>
    ///     Version of the accepted privacy policy.
    /// </summary>
    public required string PrivacyPolicyVersion { get; init; }

    /// <summary>
    ///     UTC timestamp when consent was accepted.
    /// </summary>
    public required DateTimeOffset AcceptedAtUtc { get; init; }

    /// <summary>
    ///     Secure hash of the source IP address.
    ///     GDPR Best Practice: Stores hash instead of raw personally identifiable information (PII).
    /// </summary>
    public required string SourceIpHash { get; init; }

    /// <summary>
    ///     Factory method enforcing domain invariants.
    /// </summary>
    public static ConsentInfo Create(
        bool accepted,
        string policyVersion,
        string sourceIpHash,
        DateTimeOffset timestamp)
    {
        if (!accepted)
        {
            throw new InvalidOperationException(
                "Consent invariant violated: Terms must be explicitly accepted.");
        }

        if (string.IsNullOrWhiteSpace(policyVersion))
        {
            throw new ArgumentException(
                "Privacy policy version is required.", nameof(policyVersion));
        }

        if (string.IsNullOrWhiteSpace(sourceIpHash))
        {
            throw new ArgumentException(
                "Source IP hash is required and cannot be empty.", nameof(sourceIpHash));
        }

        return new ConsentInfo
        {
            TermsAccepted = accepted,
            PrivacyPolicyVersion = policyVersion,
            AcceptedAtUtc = timestamp,
            SourceIpHash = sourceIpHash
        };
    }
}
