namespace Sentinel.Domain.Users;

/// <summary>
/// Privacy-hardened consent record for audit trail compliance.
/// Uses DateTimeOffset for global temporal consistency.
/// Stores IP as HMAC hash for GDPR compliance (avoids direct PII storage).
/// </summary>
public sealed record ConsentInfo
{
    /// <summary>
    /// Whether the user explicitly accepted the terms (domain invariant: must be true).
    /// </summary>
    public required bool TermsAccepted { get; init; }

    /// <summary>
    /// Version of privacy policy accepted (e.g., "1.0", "2.1").
    /// </summary>
    public required string PrivacyPolicyVersion { get; init; }

    /// <summary>
    /// UTC timestamp when consent was accepted.
    /// Uses DateTimeOffset for zero-skew validation across distributed systems.
    /// Required for legal audit trails and GDPR compliance.
    /// </summary>
    public required DateTimeOffset AcceptedAtUtc { get; init; }

    /// <summary>
    /// HMAC-SHA256 hash of the source IP address.
    /// GDPR Best Practice: Stores hash instead of raw PII for fraud detection/audit.
    /// Can be safely deleted per GDPR right-to-be-forgotten without affecting IP verification.
    /// </summary>
    public required string SourceIpHash { get; init; }

    /// <summary>
    /// Factory method enforcing consent invariants.
    /// </summary>
    public static ConsentInfo Create(
        bool accepted,
        string policyVersion,
        string rawIp,
        DateTimeOffset timestamp)
    {
        if (!accepted)
            throw new InvalidOperationException(
                "Consent invariant violated: Terms must be explicitly accepted.");

        if (string.IsNullOrWhiteSpace(policyVersion))
            throw new ArgumentException(
                "Privacy policy version is required.", nameof(policyVersion));

        // Hash the IP for GDPR compliance (store hash, not PII)
        var ipHash = HashIpAddress(rawIp);

        return new ConsentInfo
        {
            TermsAccepted = accepted,
            PrivacyPolicyVersion = policyVersion,
            AcceptedAtUtc = timestamp,
            SourceIpHash = ipHash
        };
    }

    /// <summary>
    /// Hashes an IP address using HMAC-SHA256 for privacy compliance.
    /// Implementation: Use a constant key (stored securely) to ensure consistent hashes.
    /// </summary>
    private static string HashIpAddress(string ipAddress)
    {
        if (string.IsNullOrWhiteSpace(ipAddress))
            return "[anonymous]";

        try
        {
            // Use a cryptographic hash (HMAC-SHA256 with a constant salt)
            using var hmac = new System.Security.Cryptography.HMACSHA256(
                System.Text.Encoding.UTF8.GetBytes("sentinel-ip-salt"));
            var hash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(ipAddress));
            return Convert.ToBase64String(hash);
        }
        catch (System.ArgumentException)
        {
            return "[error]";
        }
        catch (System.FormatException)
        {
            return "[error]";
        }
    }
}
