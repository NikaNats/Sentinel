using Sentinel.EntityFrameworkCore.Models;

namespace Sentinel.EntityFrameworkCore;

/// <summary>
///     Entity Framework context for Sentinel security caches.
/// </summary>
public sealed class SentinelSecurityDbContext : DbContext
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

        // JTI Replay Cache entity configuration
        modelBuilder.Entity<JtiReplayCacheEntry>()
            .HasKey(e => e.Jti);

        modelBuilder.Entity<JtiReplayCacheEntry>()
            .Property(e => e.CreatedAt)
            .ValueGeneratedOnAdd();

        modelBuilder.Entity<JtiReplayCacheEntry>()
            .HasIndex(e => e.ExpiresAt);

        // DPoP Nonce Store entity configuration (thumbprint is unique key, one nonce per client at a time)
        modelBuilder.Entity<DpopNonceEntry>()
            .HasKey(e => e.Thumbprint);

        modelBuilder.Entity<DpopNonceEntry>()
            .Property(e => e.CreatedAt)
            .ValueGeneratedOnAdd();

        modelBuilder.Entity<DpopNonceEntry>()
            .HasIndex(e => e.ExpiresAt);

        // Session Blacklist entity configuration
        modelBuilder.Entity<SessionBlacklistEntry>()
            .HasKey(e => e.SessionId);

        modelBuilder.Entity<SessionBlacklistEntry>()
            .Property(e => e.CreatedAt)
            .ValueGeneratedOnAdd();

        modelBuilder.Entity<SessionBlacklistEntry>()
            .HasIndex(e => e.ExpiresAt);
    }
}
