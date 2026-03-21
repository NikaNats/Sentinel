using Sentinel.Application.Models;
using Sentinel.Infrastructure.Cache;

namespace Sentinel.Tests.Unit;

public sealed class InMemoryDocumentStoreOwnershipTests
{
    [Fact]
    public async Task GetByIdAsync_WhenOwnerMatches_ReturnsDocument()
    {
        var store = new InMemoryDocumentStore();
        var created = await store.CreateAsync("owner-1", new CreateDocumentRequest("title", "content"),
            CancellationToken.None);

        var result = await store.GetByIdAsync(created.Id, "owner-1", CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal("owner-1", result!.OwnerSub);
        Assert.Equal("title", result.Title);
        Assert.Equal("content", result.Content);
    }

    [Fact]
    public async Task GetByIdAsync_WhenOwnerDoesNotMatch_ReturnsNull()
    {
        var store = new InMemoryDocumentStore();
        var created = await store.CreateAsync("owner-1", new CreateDocumentRequest("title", "content"),
            CancellationToken.None);

        var result = await store.GetByIdAsync(created.Id, "owner-2", CancellationToken.None);

        Assert.Null(result);
    }
}
