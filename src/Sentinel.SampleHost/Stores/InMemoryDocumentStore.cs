using System.Collections.Concurrent;
using Sentinel.SampleHost.Models;

namespace Sentinel.SampleHost.Stores;

internal sealed class InMemoryDocumentStore(TimeProvider? timeProvider = null) : IDocumentStore
{
    private readonly ConcurrentDictionary<Guid, DocumentState> documents = new();
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    async Task<IReadOnlyCollection<DocumentDto>> IDocumentStore.ListAsync(
        string ownerSub, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var results = documents.Values
            .Where(d => string.Equals(d.OwnerSub, ownerSub, StringComparison.Ordinal))
            .OrderByDescending(d => d.UpdatedAtUtc)
            .Select(Map)
            .ToArray();

        return await Task.FromResult<IReadOnlyCollection<DocumentDto>>(results);
    }

    async Task<DocumentDto?> IDocumentStore.GetByIdAsync(
        Guid id, string ownerSub, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!documents.TryGetValue(id, out var state)
            || !string.Equals(state.OwnerSub, ownerSub, StringComparison.Ordinal))
        {
            return await Task.FromResult<DocumentDto?>(null);
        }

        return await Task.FromResult<DocumentDto?>(Map(state));
    }

    async Task<DocumentDto> IDocumentStore.CreateAsync(
        string ownerSub, CreateDocumentRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var now = _timeProvider.GetUtcNow();
        var state = new DocumentState(
            Guid.NewGuid(),
            ownerSub,
            request.Title,
            request.Content,
            now,
            now);

        documents[state.Id] = state;
        return await Task.FromResult(Map(state));
    }

    async Task<DocumentDto?> IDocumentStore.UpdateAsync(
        Guid id, string ownerSub, UpdateDocumentRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var spinWait = new SpinWait();

        while (documents.TryGetValue(id, out var current))
        {
            if (!string.Equals(current.OwnerSub, ownerSub, StringComparison.Ordinal))
            {
                return await Task.FromResult<DocumentDto?>(null);
            }

            var updated = current with
            {
                Title = request.Title,
                Content = request.Content,
                UpdatedAtUtc = _timeProvider.GetUtcNow()
            };

            if (documents.TryUpdate(id, updated, current))
            {
                return await Task.FromResult<DocumentDto?>(Map(updated));
            }

            spinWait.SpinOnce();
        }

        return await Task.FromResult<DocumentDto?>(null);
    }

    async Task<bool> IDocumentStore.DeleteAsync(Guid id, string ownerSub, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!documents.TryGetValue(id, out var existing)
            || !string.Equals(existing.OwnerSub, ownerSub, StringComparison.Ordinal))
        {
            return await Task.FromResult(false);
        }

        var deleted = documents.TryRemove(new KeyValuePair<Guid, DocumentState>(id, existing));
        return await Task.FromResult(deleted);
    }

    private static DocumentDto Map(DocumentState state)
    {
        return new DocumentDto(
            state.Id,
            state.OwnerSub,
            state.Title,
            state.Content,
            state.CreatedAtUtc,
            state.UpdatedAtUtc);
    }

    private sealed record DocumentState(
        Guid Id,
        string OwnerSub,
        string Title,
        string Content,
        DateTimeOffset CreatedAtUtc,
        DateTimeOffset UpdatedAtUtc);
}
