using System.ComponentModel.DataAnnotations;

namespace Sentinel.Security.Abstractions.Options;

/// <summary>
///     Configuration for RFC 9449 DPoP proof validation.
///     Hardened for FAPI 2.0 compliance.
/// </summary>
public sealed class DPoPOptions
{
    /// <summary>
    ///     Configuration section name for appsettings.json.
    /// </summary>
    public const string SectionName = "DPoP";

    /// <summary>
    ///     Gets or sets the allowed clock skew for proof timestamp validation (seconds).
    ///     Strictly set to 10 seconds default per FAPI 2.0. Bounded up to 300 for testing.
    /// </summary>
    [Range(0, 300)]
    public int AllowedClockSkewSeconds { get; set; } = 10;

    /// <summary>
    ///     Gets or sets the lifetime for DPoP proofs (seconds).
    ///     Proofs older than this value are rejected.
    /// </summary>
    [Range(1, 300)]
    public int ProofLifetimeSeconds { get; set; } = 60;

    /// <summary>
    ///     Gets or sets whether nonce challenges are required.
    /// </summary>
    public bool RequireNonce { get; set; }

    /// <summary>
    ///     Gets or sets allowed JWS algorithms for proof JWTs.
    ///     STRICT FAPI 2.0 INVARIANT: restricted to PS256 and ES256 only.
    /// </summary>
    public string[] AllowedAlgorithms { get; set; } = ["PS256", "ES256"];
}
