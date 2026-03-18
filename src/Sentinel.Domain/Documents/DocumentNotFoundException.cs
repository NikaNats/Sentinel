namespace Sentinel.Domain.Documents;

public sealed class DocumentNotFoundException(Guid id)
    : Exception($"Document '{id}' not found or access denied.");
