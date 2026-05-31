using System.Collections.Concurrent;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Sentinel.Application.Common.Abstractions;
using Sentinel.AspNetCore.Endpoints;

namespace Sentinel.Sample.MinimalApi.Endpoints;

internal static class DocumentEndpoints
{
    public static void MapDocumentEndpoints(this IEndpointRouteBuilder routes, string prefix)
    {
        var group = routes.MapGroup(prefix)
            .RequireAuthorization()
            .WithTags("Documents");

        group.MapGet("/", ListDocuments)
            .RequireAuthorization("ScopeDocumentsRead")
            .WithName($"ListDocuments:{prefix}")
            .Produces<IEnumerable<DocumentSummaryDto>>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized);

        group.MapGet("/{id:guid}", GetDocument)
            .RequireAuthorization("ScopeDocumentsRead")
            .WithName($"GetDocument:{prefix}")
            .Produces<DocumentDetailDto>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status404NotFound);

        group.MapPost("/", CreateDocument)
            .RequireAuthorization("ScopeDocumentsWrite")
            .RequireIdempotency()
            .WithName($"CreateDocument:{prefix}")
            .Accepts<CreateDocumentRequest>("application/json")
            .Produces<DocumentSummaryDto>(StatusCodes.Status201Created)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status409Conflict);

        group.MapDelete("/{id:guid}", DeleteDocument)
            .RequireAuthorization("ScopeDocumentsWrite")
            .RequireIdempotency()
            .WithName($"DeleteDocument:{prefix}")
            .Produces(StatusCodes.Status204NoContent)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status403Forbidden);
    }

    private static IResult ListDocuments(HttpContext context, DocumentRepository repo)
    {
        var sub = context.User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(sub))
        {
            return TypedResults.Unauthorized();
        }

        var documents = repo
            .GetByOwner(sub)
            .OrderByDescending(d => d.CreatedUtc)
            .Select(d => new DocumentSummaryDto(
                d.Id,
                d.Title,
                d.EncryptedContent.Length,
                d.CreatedUtc))
            .ToList();

        return TypedResults.Ok(documents);
    }

    private static IResult GetDocument(Guid id, HttpContext context, DocumentRepository repo, IEncryptionService crypto)
    {
        var sub = context.User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(sub))
        {
            return TypedResults.Unauthorized();
        }

        if (!repo.TryGetByOwner(id, sub, out var document))
        {
            return TypedResults.NotFound();
        }

        var plainText = crypto.Decrypt(document.EncryptedContent);

        return TypedResults.Ok(new DocumentDetailDto(
            document.Id,
            document.Title,
            CreatePreview(plainText),
            document.EncryptedContent.Length,
            document.CreatedUtc));
    }

    private static IResult CreateDocument(
        CreateDocumentRequest request,
        HttpContext context,
        DocumentRepository repo,
        IEncryptionService crypto)
    {
        var sub = context.User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(sub))
        {
            return TypedResults.Unauthorized();
        }

        var title = request.Title?.Trim();
        var content = request.Content?.Trim();

        if (string.IsNullOrWhiteSpace(title) || string.IsNullOrWhiteSpace(content))
        {
            return TypedResults.Problem(
                type: "/errors/invalid-request",
                title: "Invalid request payload",
                detail: "Title and content are required.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        if (title.Length > 120)
        {
            return TypedResults.Problem(
                type: "/errors/invalid-request",
                title: "Invalid request payload",
                detail: "Title must be 120 characters or fewer.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        if (string.Equals(title, "secrets", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.Headers.Append(
                "WWW-Authenticate",
                "DPoP error=\"insufficient_user_authentication\", error_description=\"Surgical authorization required\"");

            return TypedResults.Problem(
                type: "/errors/insufficient-user-authentication",
                title: "Surgical authorization required",
                statusCode: StatusCodes.Status401Unauthorized);
        }

        var encryptedContent = crypto.Encrypt(content);

        var doc = new DocumentRecord(
            Guid.NewGuid(),
            sub,
            title,
            encryptedContent,
            DateTimeOffset.UtcNow);

        repo.Add(doc);

        return TypedResults.Created(
            $"/api/v1/documents/{doc.Id}",
            new DocumentSummaryDto(doc.Id, doc.Title, doc.EncryptedContent.Length, doc.CreatedUtc));
    }

    private static IResult DeleteDocument(Guid id, HttpContext context, DocumentRepository repo)
    {
        var sub = context.User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(sub))
        {
            return TypedResults.Unauthorized();
        }

        if (context.Connection.ClientCertificate is null)
        {
            return TypedResults.Problem(
                type: "/errors/mtls-binding-failed",
                title: "mTLS certificate is required",
                statusCode: StatusCodes.Status403Forbidden);
        }

        var success = repo.Delete(id, sub);
        return success
            ? TypedResults.NoContent()
            : TypedResults.NotFound();
    }

    private static string CreatePreview(string content)
    {
        const int previewLength = 120;

        if (content.Length <= previewLength)
        {
            return content;
        }

        return string.Concat(content.AsSpan(0, previewLength), "...");
    }
}

public sealed record CreateDocumentRequest(string Title, string Content);

public sealed record DocumentSummaryDto(Guid Id, string Title, int EncryptedBytes, DateTimeOffset CreatedUtc);

public sealed record DocumentDetailDto(
    Guid Id,
    string Title,
    string ContentPreview,
    int EncryptedBytes,
    DateTimeOffset CreatedUtc);

internal sealed record DocumentRecord(
    Guid Id,
    string OwnerSub,
    string Title,
    byte[] EncryptedContent,
    DateTimeOffset CreatedUtc);

internal sealed class DocumentRepository
{
    private readonly ConcurrentDictionary<Guid, DocumentRecord> _store = new();

    public IEnumerable<DocumentRecord> GetByOwner(string sub)
    {
        return _store.Values.Where(x => x.OwnerSub == sub);
    }

    public bool TryGetByOwner(Guid id, string sub, out DocumentRecord document)
    {
        if (_store.TryGetValue(id, out var found) && found.OwnerSub == sub)
        {
            document = found;
            return true;
        }

        document = default!;
        return false;
    }

    public void Add(DocumentRecord doc)
    {
        _store[doc.Id] = doc;
    }

    public bool Delete(Guid id, string sub)
    {
        if (!_store.TryGetValue(id, out var doc))
        {
            return false;
        }

        if (doc.OwnerSub != sub)
        {
            return false;
        }

        return _store.TryRemove(id, out _);
    }
}
