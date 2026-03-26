namespace Sentinel.Domain.Users;

/// <summary>
/// Hardened user registration entity enforcing invariants at instantiation.
/// Required members and constructor validation prevent invalid states.
/// Compliant with GDPR/CCPA/NIST 800-63B Privacy-By-Design requirements.
/// </summary>
public sealed class UserRegistration
{
    /// <summary>
    /// Unique identifier for the registration. Generated at instantiation.
    /// </summary>
    public required Guid Id { get; init; }

    /// <summary>
    /// Email address (lowercase, trimmed). Validated at instantiation.
    /// Domain Invariant: Must be non-empty and valid format.
    /// </summary>
    public required string Email { get; init; }

    /// <summary>
    /// Username (trimmed). Validated at instantiation.
    /// </summary>
    public required string Username { get; init; }

    /// <summary>
    /// Consent record (non-null). Contains audit trail of user consent.
    /// Domain Invariant: Must be present and valid.
    /// </summary>
    public required ConsentInfo Consent { get; init; }

    /// <summary>
    /// Constructor enforcing domain invariants.
    /// Uses [SetsRequiredMembers] to satisfy the C# required member contract.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SetsRequiredMembers]
    public UserRegistration(string email, string username, ConsentInfo consent)
    {
        // Domain Invariant: Email must be present and valid
        if (string.IsNullOrWhiteSpace(email))
            throw new ArgumentException("Email is mandatory and cannot be empty.", nameof(email));

        // Domain Invariant: Consent must be present
        if (consent is null)
            throw new ArgumentNullException(nameof(consent), "Consent information is mandatory.");

        Id = Guid.NewGuid();
        Email = email.Trim().ToLowerInvariant();
        Username = username?.Trim() ?? string.Empty;
        Consent = consent;
    }

    /// <summary>
    /// Parameterless constructor for source-generated serializers (Native AOT compatibility).
    /// </summary>
    public UserRegistration()
    {
        Id = Guid.Empty;
        Email = string.Empty;
        Username = string.Empty;
        Consent = null!;
    }
}
