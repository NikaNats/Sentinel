using System.ComponentModel.DataAnnotations.Schema;

namespace Sentinel.EntityFrameworkCore.Models;

/// <summary>
///     Entity model for storing JWT IDs (jti claims) for replay detection.
/// </summary>
[Table("jti_replay_cache")]
public sealed class JtiReplayCacheEntry
{
    [Column("id")] public required string Jti { get; set; }

    [Column("expires_at")] public required DateTimeOffset ExpiresAt { get; set; }

    [Column("created_at")] public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>
///     Entity model for storing DPoP nonces.
/// </summary>
[Table("dpop_nonce_store")]
public sealed class DpopNonceEntry
{
    [Column("id")] public required string Thumbprint { get; set; }

    [Column("nonce")] public required string Nonce { get; set; }

    [Column("expires_at")] public required DateTimeOffset ExpiresAt { get; set; }

    [Column("created_at")] public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>
///     Entity model for storing blacklisted sessions.
/// </summary>
[Table("session_blacklist")]
public sealed class SessionBlacklistEntry
{
    [Column("id")] public required string SessionId { get; set; }

    [Column("expires_at")] public required DateTimeOffset ExpiresAt { get; set; }

    [Column("created_at")] public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
