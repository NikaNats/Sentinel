using System.Collections.ObjectModel;
using System.ComponentModel.DataAnnotations;

namespace Sentinel.Security.Abstractions.Options;

/// <summary>
/// Configuration for RFC 9449 DPoP proof validation.
/// </summary>
public sealed class DPoPOptions
{
    /// <summary>
    /// Configuration section name for appsettings.json.
    /// </summary>
    public const string SectionName = "DPoP";

    /// <summary>
    /// Gets or sets the allowed clock skew for proof timestamp validation (seconds).
    /// </summary>
    [Range(0, 3600)]
    public int AllowedClockSkewSeconds { get; set; } = 60;

    /// <summary>
    /// Gets or sets the lifetime for DPoP proofs (seconds).
    /// Proofs older than this value are rejected.
    /// </summary>
    [Range(1, 3600)]
    public int ProofLifetimeSeconds { get; set; } = 120;

    /// <summary>
    /// Gets or sets whether nonce challenges are required.
    /// </summary>
    public bool RequireNonce { get; set; }

    /// <summary>
    /// Gets or sets allowed JWS algorithms for proof JWTs.
    /// Defaults to ES256, ES384, ES512 (NIST curves) + EdDSA.
    /// </summary>
    public IList<string> AllowedAlgorithms { get; } =
        new List<string> { "ES256", "ES384", "ES512", "EdDSA" };
}
