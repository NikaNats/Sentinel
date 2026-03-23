using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sentinel.Application.Auth;
using Sentinel.Middleware.Filters;
using Sentinel.SampleHost.Models;
using Sentinel.SampleHost.Stores;

namespace Sentinel.SampleHost.Controllers;

[ApiController]
[Route("v1/documents")]
public sealed class DocumentsController(IDocumentStore documentStore, ILogger<DocumentsController> logger)
    : ControllerBase
{
    private string? CurrentSub => User.FindFirst("sub")?.Value;

    [HttpGet]
    [Authorize(Policy = Policies.DocumentsRead)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> ListDocuments(CancellationToken cancellationToken)
    {
        var subject = CurrentSub;
        if (string.IsNullOrWhiteSpace(subject))
        {
            return Unauthorized();
        }

        var documents = await documentStore.ListAsync(subject, cancellationToken);
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
        var subject = CurrentSub;
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
    public async Task<IActionResult> CreateDocument([FromBody] CreateDocumentRequest request,
        CancellationToken cancellationToken)
    {
        var subject = CurrentSub;
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
    public async Task<IActionResult> UpdateDocument(Guid id, [FromBody] UpdateDocumentRequest request,
        CancellationToken cancellationToken)
    {
        var subject = CurrentSub;
        if (string.IsNullOrWhiteSpace(subject))
        {
            return Unauthorized();
        }

        var updated = await documentStore.UpdateAsync(id, subject, request, cancellationToken);
        if (updated is null)
        {
            return NotFound();
        }

        return Ok(updated);
    }

    [HttpDelete("{id}")]
    [Authorize(Policy = Policies.DocumentsWrite)]
    [RequireMtlsBinding]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> DeleteDocument(Guid id, CancellationToken cancellationToken)
    {
        var subject = CurrentSub;
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
