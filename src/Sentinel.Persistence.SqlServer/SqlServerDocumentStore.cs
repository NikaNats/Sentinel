using Microsoft.EntityFrameworkCore;
using Sentinel.Domain.Documents;
using Sentinel.Persistence.Core;

namespace Sentinel.Persistence.SqlServer;

public sealed class SqlServerDocumentStore(
    SqlServerSentinelDbContext db,
    ILogger<SqlServerDocumentStore> logger)
    : EfDocumentStore<SqlServerSentinelDbContext>(db, logger)
{
    protected override IQueryable<Document> ApplySearch(IQueryable<Document> query, string searchTerm) =>
        query.Where(document =>
            EF.Functions.Like(document.Title, $"%{searchTerm}%")
            || EF.Functions.Like(document.Content, $"%{searchTerm}%"));

    protected override string GetRowVersion(Document document) =>
        Convert.ToBase64String(document.RowVersion);

    protected override void SetOriginalRowVersion(Document document, string rowVersion) =>
        Db.Entry(document).Property(entity => entity.RowVersion).OriginalValue =
            Convert.FromBase64String(rowVersion);
}
