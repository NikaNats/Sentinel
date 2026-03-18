using System.Collections.Concurrent;
using System.Globalization;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Application.Models;
using Sentinel.Domain.Documents;

namespace Sentinel.Infrastructure.Cache;

public sealed class InMemoryDocumentStore : IDocumentStore
{
    private readonly ConcurrentDictionary<Guid, DocumentState> documents = new();

    public Task<PagedResult<DocumentDto>> ListAsync(string ownerSub, DocumentQuery query, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        int page = Math.Max(1, query.Page);
        int pageSize = Math.Clamp(query.PageSize, 1, 200);

        IEnumerable<DocumentState> filtered = documents.Values
            .Where(d => !d.IsDeleted && string.Equals(d.OwnerSub, ownerSub, StringComparison.Ordinal));

        if (!string.IsNullOrWhiteSpace(query.SearchTerm))
        {
            string term = query.SearchTerm.Trim();
            filtered = filtered.Where(d =>
                d.Title.Contains(term, StringComparison.OrdinalIgnoreCase)
                || d.Content.Contains(term, StringComparison.OrdinalIgnoreCase));
        }

        filtered = query.SortBy switch
        {
            DocumentSortBy.UpdatedAtAsc => filtered.OrderBy(d => d.UpdatedAtUtc),
            DocumentSortBy.TitleAsc => filtered.OrderBy(d => d.Title, StringComparer.Ordinal),
            DocumentSortBy.TitleDesc => filtered.OrderByDescending(d => d.Title, StringComparer.Ordinal),
            DocumentSortBy.CreatedAtDesc => filtered.OrderByDescending(d => d.CreatedAtUtc),
            _ => filtered.OrderByDescending(d => d.UpdatedAtUtc)
        };

        DocumentDto[] items = filtered
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(Map)
            .ToArray();

        int totalCount = filtered.Count();
        return Task.FromResult(new PagedResult<DocumentDto>(items, totalCount, page, pageSize));
    }

    public Task<DocumentDto?> GetByIdAsync(Guid id, string ownerSub, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!documents.TryGetValue(id, out DocumentState? state)
            || state.IsDeleted
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
            UpdatedAtUtc: now,
            Version: 1,
            IsDeleted: false,
            DeletedAtUtc: null);

        documents[state.Id] = state;
        return Task.FromResult(Map(state));
    }

    public Task<DocumentDto?> UpdateAsync(Guid id, string ownerSub, UpdateDocumentRequest request, string rowVersion, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        while (documents.TryGetValue(id, out var current))
        {
            if (current.IsDeleted || !string.Equals(current.OwnerSub, ownerSub, StringComparison.Ordinal))
            {
                return Task.FromResult<DocumentDto?>(null);
            }

            if (!string.Equals(current.RowVersion, rowVersion, StringComparison.Ordinal))
            {
                throw new DocumentConcurrencyException(id);
            }

            var updated = current with
            {
                Title = request.Title,
                Content = request.Content,
                UpdatedAtUtc = DateTimeOffset.UtcNow,
                Version = current.Version + 1
            };

            if (documents.TryUpdate(id, updated, current))
            {
                return Task.FromResult<DocumentDto?>(Map(updated));
            }
        }

        return Task.FromResult<DocumentDto?>(null);
    }

    public Task<bool> DeleteAsync(Guid id, string ownerSub, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!documents.TryGetValue(id, out var existing)
            || existing.IsDeleted
            || !string.Equals(existing.OwnerSub, ownerSub, StringComparison.Ordinal))
        {
            return Task.FromResult(false);
        }

        var deleted = existing with
        {
            IsDeleted = true,
            DeletedAtUtc = DateTimeOffset.UtcNow,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
            Version = existing.Version + 1
        };

        return Task.FromResult(documents.TryUpdate(id, deleted, existing));
    }

    private static DocumentDto Map(DocumentState state)
    {
        return new DocumentDto(
            state.Id,
            state.OwnerSub,
            state.Title,
            state.Content,
            state.CreatedAtUtc,
            state.UpdatedAtUtc,
            state.RowVersion);
    }

    private sealed record DocumentState(
        Guid Id,
        string OwnerSub,
        string Title,
        string Content,
        DateTimeOffset CreatedAtUtc,
        DateTimeOffset UpdatedAtUtc,
        long Version,
        bool IsDeleted,
        DateTimeOffset? DeletedAtUtc)
    {
        public string RowVersion => Version.ToString(CultureInfo.InvariantCulture);
    }
}
