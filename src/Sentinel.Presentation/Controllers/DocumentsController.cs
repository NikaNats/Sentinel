using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sentinel.Application.Auth;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Application.Models;
using Sentinel.Domain.Documents;
using Sentinel.Middleware.Filters;

namespace Sentinel.Controllers;

[ApiController]
[Route("v1/documents")]
public sealed class DocumentsController(IDocumentStore documentStore, ILogger<DocumentsController> logger) : ControllerBase
{
    [HttpGet]
    [Authorize(Policy = Policies.DocumentsRead)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> ListDocuments(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        [FromQuery] string? searchTerm = null,
        [FromQuery] DocumentSortBy sortBy = DocumentSortBy.UpdatedAtDesc,
        CancellationToken cancellationToken = default)
    {
        var subject = User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(subject))
        {
            return Unauthorized();
        }

        var documents = await documentStore.ListAsync(
            subject,
            new DocumentQuery(page, pageSize, searchTerm, sortBy),
            cancellationToken);
        return Ok(documents);
    }

    [HttpGet("{id}")]
    [Authorize(Policy = Policies.DocumentsRead)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> GetDocument(Guid id, CancellationToken cancellationToken)
    {
        var subject = User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(subject))
        {
            return Unauthorized();
        }

        var document = await documentStore.GetByIdAsync(id, subject, cancellationToken);
        if (document is null)
        {
            return NotFound();
        }

        return Ok(document);
    }

    [HttpPost]
    [Authorize(Policy = Policies.DocumentsWrite)]
    [RequireIdempotency]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> CreateDocument([FromBody] CreateDocumentRequest request, CancellationToken cancellationToken)
    {
        var subject = User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(subject))
        {
            return Unauthorized();
        }

        var created = await documentStore.CreateAsync(subject, request, cancellationToken);
        logger.LogInformation(
            "security:document_created document_id={DocumentId} sub={Subject}",
            created.Id,
            subject);

        return CreatedAtAction(nameof(GetDocument), new { id = created.Id }, created);
    }

    [HttpPut("{id}")]
    [Authorize(Policy = Policies.DocumentsWrite)]
    [RequireIdempotency]
    [RequireMtlsBinding]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> UpdateDocument(Guid id, [FromBody] UpdateDocumentRequest request, CancellationToken cancellationToken)
    {
        var subject = User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(subject))
        {
            return Unauthorized();
        }

        try
        {
            var updated = await documentStore.UpdateAsync(id, subject, request, request.RowVersion, cancellationToken);
            if (updated is null)
            {
                return NotFound();
            }

            return Ok(updated);
        }
        catch (DocumentConcurrencyException)
        {
            return Conflict(new ProblemDetails
            {
                Type = "/errors/document-conflict",
                Title = "Concurrent Modification",
                Detail = "The document was modified by another request. Fetch the latest version and retry.",
                Status = StatusCodes.Status409Conflict
            });
        }
    }

    [HttpDelete("{id}")]
    [Authorize(Policy = Policies.DocumentsWrite)]
    [RequireIdempotency]
    [RequireMtlsBinding]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> DeleteDocument(Guid id, CancellationToken cancellationToken)
    {
        var subject = User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(subject))
        {
            return Unauthorized();
        }

        var deleted = await documentStore.DeleteAsync(id, subject, cancellationToken);
        if (!deleted)
        {
            return NotFound();
        }

        logger.LogInformation(
            "security:document_deleted document_id={DocumentId} sub={Subject}",
            id,
            subject);

        return NoContent();
    }
}
