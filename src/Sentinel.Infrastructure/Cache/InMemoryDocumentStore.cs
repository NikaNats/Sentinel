using System.Collections.Concurrent;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Application.Models;

namespace Sentinel.Infrastructure.Cache;

public sealed class InMemoryDocumentStore : IDocumentStore
{
    private readonly ConcurrentDictionary<Guid, DocumentState> documents = new();

    public Task<IReadOnlyCollection<DocumentDto>> ListAsync(string ownerSub, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var results = documents.Values
            .Where(d => string.Equals(d.OwnerSub, ownerSub, StringComparison.Ordinal))
            .OrderByDescending(d => d.UpdatedAtUtc)
            .Select(Map)
            .ToArray();

        return Task.FromResult<IReadOnlyCollection<DocumentDto>>(results);
    }

    public Task<DocumentDto?> GetByIdAsync(Guid id, string ownerSub, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!documents.TryGetValue(id, out var state)
            || !string.Equals(state.OwnerSub, ownerSub, StringComparison.Ordinal))
        {
            return Task.FromResult<DocumentDto?>(null);
        }

        return Task.FromResult<DocumentDto?>(Map(state));
    }

    public Task<DocumentDto> CreateAsync(string ownerSub, CreateDocumentRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var now = DateTimeOffset.UtcNow;
        var state = new DocumentState(
            Id: Guid.NewGuid(),
            OwnerSub: ownerSub,
            Title: request.Title,
            Content: request.Content,
            CreatedAtUtc: now,
            UpdatedAtUtc: now);

        documents[state.Id] = state;
        return Task.FromResult(Map(state));
    }

    public Task<DocumentDto?> UpdateAsync(Guid id, string ownerSub, UpdateDocumentRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var spinWait = new SpinWait();

        while (documents.TryGetValue(id, out var current))
        {
            if (!string.Equals(current.OwnerSub, ownerSub, StringComparison.Ordinal))
            {
                return Task.FromResult<DocumentDto?>(null);
            }

            var updated = current with
            {
                Title = request.Title,
                Content = request.Content,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };

            if (documents.TryUpdate(id, updated, current))
            {
                return Task.FromResult<DocumentDto?>(Map(updated));
            }

            spinWait.SpinOnce();
        }

        return Task.FromResult<DocumentDto?>(null);
    }

    public Task<bool> DeleteAsync(Guid id, string ownerSub, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!documents.TryGetValue(id, out var existing)
            || !string.Equals(existing.OwnerSub, ownerSub, StringComparison.Ordinal))
        {
            return Task.FromResult(false);
        }

        var deleted = documents.TryRemove(new KeyValuePair<Guid, DocumentState>(id, existing));
        return Task.FromResult(deleted);
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
