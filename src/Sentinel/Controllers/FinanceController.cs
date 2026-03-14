using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Sentinel.Controllers;

[ApiController]
[Route("v1/finance")]
public sealed class FinanceController : ControllerBase
{
    [HttpPost("transfer")]
    [Authorize(Policy = "RequireAcr3")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public IActionResult MakeTransfer()
    {
        return Ok(new { Status = "Success" });
    }
}
