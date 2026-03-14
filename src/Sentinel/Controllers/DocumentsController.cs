using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Sentinel.Controllers;

[ApiController]
[Route("v1/documents")]
public sealed class DocumentsController : ControllerBase
{
    [HttpGet("{id}")]
    [Authorize(Policy = "Document:Read")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public IActionResult GetDocument(Guid id)
    {
        return Ok(new { DocumentId = id, Content = "Top Secret Government Data" });
    }

    [HttpDelete("{id}")]
    [Authorize(Policy = "Document:Delete")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public IActionResult DeleteDocument(Guid id)
    {
        return NoContent();
    }
}
