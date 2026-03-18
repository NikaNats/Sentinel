using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Sentinel.Domain.Documents;
using Sentinel.Persistence.Core;

namespace Sentinel.Persistence.SqlServer;

public sealed class SqlServerSentinelDbContext(
    DbContextOptions<SqlServerSentinelDbContext> options,
    IHttpContextAccessor httpContextAccessor)
    : SentinelDbContext(options)
{
    public async Task SetCurrentUserAsync(CancellationToken cancellationToken = default)
    {
        string sub = httpContextAccessor.HttpContext?.User.FindFirst("sub")?.Value ?? string.Empty;

        await Database.ExecuteSqlRawAsync(
            "EXEC sys.sp_set_session_context @key = N'sentinel_sub', @value = {0}, @read_only = 1",
            [sub],
            cancellationToken);
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<Document>()
            .Property(document => document.RowVersion)
            .IsRowVersion();
    }
}
