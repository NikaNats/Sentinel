using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Sentinel.Domain.Documents;
using Sentinel.Persistence.Core;

namespace Sentinel.Persistence.Postgres;

public sealed class PostgresSentinelDbContext(
    DbContextOptions<PostgresSentinelDbContext> options,
    IHttpContextAccessor httpContextAccessor)
    : SentinelDbContext(options)
{
    public async Task SetCurrentUserAsync(CancellationToken cancellationToken = default)
    {
        string sub = httpContextAccessor.HttpContext?.User.FindFirst("sub")?.Value ?? string.Empty;

        await Database.ExecuteSqlRawAsync(
            "SELECT set_config('sentinel.current_sub', {0}, true)",
            [sub],
            cancellationToken);
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<Document>().Ignore(document => document.RowVersion);
        builder.Entity<Document>().UseXminAsConcurrencyToken();
    }
}
