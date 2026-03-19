using Sentinel.Application.Models;

namespace Sentinel.Application.Common.Abstractions;

public interface IDocumentStore
{
    Task<IReadOnlyCollection<DocumentDto>> ListAsync(string ownerSub, CancellationToken cancellationToken);
    Task<DocumentDto?> GetByIdAsync(Guid id, string ownerSub, CancellationToken cancellationToken);
    Task<DocumentDto> CreateAsync(string ownerSub, CreateDocumentRequest request, CancellationToken cancellationToken);
    Task<DocumentDto?> UpdateAsync(Guid id, string ownerSub, UpdateDocumentRequest request, CancellationToken cancellationToken);
    Task<bool> DeleteAsync(Guid id, string ownerSub, CancellationToken cancellationToken);
}
