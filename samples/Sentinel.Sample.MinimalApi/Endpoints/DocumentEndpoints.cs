using System.Collections.Concurrent;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Sentinel.Application.Common.Abstractions;
using Sentinel.AspNetCore.Endpoints;

namespace Sentinel.Sample.MinimalApi.Endpoints;

    /// <summary>
    /// Document Management Endpoints
    ///
    /// Demonstrates:
    /// - Envelope cryptography for data at rest (IEncryptionService)
    /// - DPoP binding (required by default via middleware)
    /// - Idempotency-Key enforcement for POST (prevents duplicate document creation)
    /// - Authorization for destructive operations (DELETE requires valid token)
    /// </summary>
    internal static class DocumentEndpoints
{
    public static void MapDocumentEndpoints(this IEndpointRouteBuilder routes, string prefix)
    {
        var group = routes.MapGroup(prefix)
            .RequireAuthorization() // Base: Requires valid JWT + DPoP proof
            .WithTags("Documents");

        // GET: List all documents for authenticated user
        group.MapGet("/", ListDocuments)
            .WithName("ListDocuments")
            .Produces<IEnumerable<DocumentDto>>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized);

        // POST: Create new document (requires Idempotency-Key to prevent duplicates)
        group.MapPost("/", CreateDocument)
            .RequireIdempotency() // Enforces RFC 9110 idempotent-request semantics
            .WithName("CreateDocument")
            .Accepts<CreateDocumentRequest>("application/json")
            .Produces<DocumentDto>(StatusCodes.Status201Created)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status409Conflict); // Idempotency conflict

        // DELETE: Remove document
        group.MapDelete("/{id:guid}", DeleteDocument)
            .WithName("DeleteDocument")
            .Produces(StatusCodes.Status204NoContent)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status403Forbidden);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // HANDLER: List all documents
    // ─────────────────────────────────────────────────────────────────────────────
    private static IResult ListDocuments(HttpContext context, DocumentRepository repo)
    {
        var sub = context.User.FindFirst("sub")?.Value;
        if (sub == null)
            return TypedResults.Unauthorized();

        var documents = repo
            .GetByOwner(sub)
            .Select(d => new DocumentDto(
                d.Id,
                d.Title,
                "Encrypted",
                d.CreatedUtc))
            .ToList();

        return TypedResults.Ok(documents);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // HANDLER: Create new document with envelope encryption
    // ─────────────────────────────────────────────────────────────────────────────
    private static IResult CreateDocument(
        CreateDocumentRequest request,
        HttpContext context,
        DocumentRepository repo,
        IEncryptionService crypto)
    {
        var sub = context.User.FindFirst("sub")?.Value;
        if (sub == null)
            return TypedResults.Unauthorized();

        if (string.IsNullOrWhiteSpace(request.Title) || string.IsNullOrWhiteSpace(request.Content))
            return TypedResults.BadRequest(new { error = "Title and Content are required" });

        // ✨ ENCRYPT DATA AT REST
        // The framework handles:
        // - V1 Envelope envelope prepending (algorithm, keyId, timestamp)
        // - AES-256-GCM encryption with authenticated encryption
        // - Key rotation metadata
        byte[] encryptedContent = crypto.Encrypt(request.Content);

        var doc = new DocumentRecord(
            Guid.NewGuid(),
            sub,
            request.Title,
            encryptedContent,
            DateTime.UtcNow);

        repo.Add(doc);

        return TypedResults.Created(
            $"/api/v1/documents/{doc.Id}",
            new DocumentDto(doc.Id, doc.Title, "Encrypted", doc.CreatedUtc));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // HANDLER: Delete document (mTLS binding required)
    // ─────────────────────────────────────────────────────────────────────────────
    private static IResult DeleteDocument(Guid id, HttpContext context, DocumentRepository repo)
    {
        var sub = context.User.FindFirst("sub")?.Value;
        if (sub == null)
            return TypedResults.Unauthorized();

        var success = repo.Delete(id, sub);
        return success
            ? TypedResults.NoContent()
            : TypedResults.NotFound(new { error = "Document not found or unauthorized" });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DTOs
// ─────────────────────────────────────────────────────────────────────────────

public sealed record CreateDocumentRequest(string Title, string Content);

public sealed record DocumentDto(Guid Id, string Title, string Status, DateTime CreatedUtc);

internal sealed record DocumentRecord(
    Guid Id,
    string OwnerSub,
    string Title,
    byte[] EncryptedContent,
    DateTime CreatedUtc);

// ─────────────────────────────────────────────────────────────────────────────
// IN-MEMORY REPOSITORY (Sample purposes only; use EF Core in production)
// ─────────────────────────────────────────────────────────────────────────────

internal sealed class DocumentRepository
{
    private readonly ConcurrentDictionary<Guid, DocumentRecord> _store = new();

    /// <summary>Get all documents owned by a user.</summary>
    public IEnumerable<DocumentRecord> GetByOwner(string sub)
    {
        return _store.Values.Where(x => x.OwnerSub == sub);
    }

    /// <summary>Add or update a document.</summary>
    public void Add(DocumentRecord doc)
    {
        _store[doc.Id] = doc;
    }

    /// <summary>Delete a document if owned by user.</summary>
    public bool Delete(Guid id, string sub)
    {
        if (!_store.TryGetValue(id, out var doc))
            return false;

        // Verify ownership before deletion
        if (doc.OwnerSub != sub)
            return false;

        return _store.TryRemove(id, out _);
    }
}
