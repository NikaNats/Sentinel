using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Sentinel.Domain.Documents;
using Sentinel.Persistence.Core;

namespace Sentinel.Persistence.Postgres;

public sealed class PostgresDocumentStore(
    PostgresSentinelDbContext db,
    ILogger<PostgresDocumentStore> logger)
    : EfDocumentStore<PostgresSentinelDbContext>(db, logger)
{
    protected override IQueryable<Document> ApplySearch(IQueryable<Document> query, string searchTerm) =>
        query.Where(document =>
            EF.Functions.ILike(document.Title, $"%{searchTerm}%")
            || EF.Functions.ILike(document.Content, $"%{searchTerm}%"));

    protected override string GetRowVersion(Document document) =>
        Db.Entry(document).Property<uint>("xmin").CurrentValue.ToString(CultureInfo.InvariantCulture);

    protected override void SetOriginalRowVersion(Document document, string rowVersion)
    {
        if (!uint.TryParse(rowVersion, CultureInfo.InvariantCulture, out uint xmin))
        {
            throw new ArgumentException("Invalid rowVersion format for PostgreSQL.", nameof(rowVersion));
        }

        Db.Entry(document).Property<uint>("xmin").OriginalValue = xmin;
    }
}
