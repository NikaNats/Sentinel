using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sentinel.Application.Auth;

namespace Sentinel.Controllers;

[ApiController]
[Route("v1/documents")]
public sealed class DocumentsController : ControllerBase
{
    [HttpGet("{id}")]
    [Authorize(Policy = Policies.DocumentRead)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public IActionResult GetDocument(Guid id)
    {
        return Ok(new { DocumentId = id, Content = "Top Secret Government Data" });
    }

    [HttpDelete("{id}")]
    [Authorize(Policy = Policies.DocumentDelete)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public IActionResult DeleteDocument(Guid id)
    {
        return NoContent();
    }
}
