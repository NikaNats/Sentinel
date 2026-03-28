namespace Sentinel.EntityFrameworkCore.Models;

using System.ComponentModel.DataAnnotations.Schema;

/// <summary>
/// Entity model for storing JWT IDs (jti claims) for replay detection.
/// Sealed class for EF Core change tracker reference equality semantics.
/// </summary>
[Table("jti_replay_cache")]
public sealed class JtiReplayCacheEntry
{
    [Column("id")]
    public required string Jti { get; set; }

    [Column("expires_at")]
    public required DateTimeOffset ExpiresAt { get; set; }

    [Column("created_at")]
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>
/// Entity model for storing DPoP nonces.
/// Sealed class for EF Core change tracker reference equality semantics.
/// </summary>
[Table("dpop_nonce_store")]
public sealed class DpopNonceEntry
{
    [Column("id")]
    public required string Thumbprint { get; set; }

    [Column("nonce")]
    public required string Nonce { get; set; }

    [Column("expires_at")]
    public required DateTimeOffset ExpiresAt { get; set; }

    [Column("created_at")]
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>
/// Entity model for storing blacklisted sessions.
/// Sealed class for EF Core change tracker reference equality semantics.
/// </summary>
[Table("session_blacklist")]
public sealed class SessionBlacklistEntry
{
    [Column("id")]
    public required string SessionId { get; set; }

    [Column("expires_at")]
    public required DateTimeOffset ExpiresAt { get; set; }

    [Column("created_at")]
    public DateTimeOffset CreatedAt { get; set; }
}
