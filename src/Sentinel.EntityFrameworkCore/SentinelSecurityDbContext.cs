namespace Sentinel.EntityFrameworkCore;

using Sentinel.EntityFrameworkCore.Models;

/// <summary>
/// Entity Framework context for Sentinel security caches.
/// </summary>
public sealed partial class SentinelSecurityDbContext : DbContext
{
    public SentinelSecurityDbContext(DbContextOptions<SentinelSecurityDbContext> options)
        : base(options)
    {
    }

    public DbSet<JtiReplayCacheEntry> JtiReplayCache { get; set; } = null!;
    public DbSet<DpopNonceEntry> DpopNonceStore { get; set; } = null!;
    public DbSet<SessionBlacklistEntry> SessionBlacklist { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // JTI Replay Cache keys
        modelBuilder.Entity<JtiReplayCacheEntry>()
            .HasKey(e => e.Jti);

        modelBuilder.Entity<JtiReplayCacheEntry>()
            .HasIndex(e => e.ExpiresAt);

        // DPoP Nonce Store keys (thumbprint is unique, only one nonce per client at a time)
        modelBuilder.Entity<DpopNonceEntry>()
            .HasKey(e => e.Thumbprint);

        modelBuilder.Entity<DpopNonceEntry>()
            .HasIndex(e => e.ExpiresAt);

        // Session Blacklist keys
        modelBuilder.Entity<SessionBlacklistEntry>()
            .HasKey(e => e.SessionId);

        modelBuilder.Entity<SessionBlacklistEntry>()
            .HasIndex(e => e.ExpiresAt);
    }
}
