namespace Sentinel.EntityFrameworkCore.Models;

using System.ComponentModel.DataAnnotations.Schema;

/// <summary>
/// Entity model for storing JWT IDs (jti claims) for replay detection.
/// </summary>
[Table("jti_replay_cache")]
public sealed record JtiReplayCacheEntry
{
    [Column("id")]
    public string Jti { get; init; } = string.Empty;

    [Column("expires_at")]
    public DateTime ExpiresAt { get; init; }

    [Column("created_at")]
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Entity model for storing DPoP nonces.
/// </summary>
[Table("dpop_nonce_store")]
public sealed record DpopNonceEntry
{
    [Column("id")]
    public string Thumbprint { get; init; } = string.Empty;

    [Column("nonce")]
    public string Nonce { get; init; } = string.Empty;

    [Column("expires_at")]
    public DateTime ExpiresAt { get; init; }

    [Column("created_at")]
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Entity model for storing blacklisted sessions.
/// </summary>
[Table("session_blacklist")]
public sealed record SessionBlacklistEntry
{
    [Column("id")]
    public string SessionId { get; init; } = string.Empty;

    [Column("expires_at")]
    public DateTime ExpiresAt { get; init; }

    [Column("created_at")]
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;
}
