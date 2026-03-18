namespace Sentinel.Domain.Documents;

public sealed class DocumentConcurrencyException(Guid id)
    : Exception($"Document '{id}' was modified by another request. Retry with latest version.");
