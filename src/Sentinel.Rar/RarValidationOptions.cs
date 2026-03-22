namespace Sentinel.RAR;

/// <summary>
/// Configuration options for Rich Authorization Request (RAR) validation.
/// </summary>
public sealed class RarValidationOptions
{
    /// <summary>
    /// Gets or sets the token precision tolerance for monetary amount comparisons.
    /// Used when validating financial transactions to account for rounding differences.
    /// Default: 0.0001m (one tenth of a cent for most currencies).
    /// </summary>
    public decimal MonetaryPrecisionTolerance { get; init; } = 0.0001m;

    /// <summary>
    /// Gets or sets a value indicating whether string comparisons are case-sensitive.
    /// Affects authorization_details type matching and currency code matching.
    /// Default: false (case-insensitive for flexibility).
    /// </summary>
    public bool CaseSensitiveComparison { get; init; }

    /// <summary>
    /// Gets or sets a value indicating whether to require an exact match for authorization details.
    /// When false, allows for additional properties in requests not mentioned in auth details.
    /// Default: false (allows flexible request payloads).
    /// </summary>
    public bool RequireExactMatch { get; init; }

    /// <summary>
    /// Gets or sets the maximum number of authorization details expected in a claim.
    /// Helps prevent DoS attacks with excessively large authorization detail arrays.
    /// Default: 100.
    /// </summary>
    public int MaxAuthorizationDetailsCount { get; init; } = 100;
}
