using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sentinel.Application.Auth;
using Sentinel.Middleware.Filters;

namespace Sentinel.Controllers;

[ApiController]
[Route("v1/finance")]
public sealed class FinanceController : ControllerBase
{
    [HttpPost("transfer")]
    [Authorize(Policy = Policies.RequireAcr3)]
    [RequireIdempotency]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public IActionResult MakeTransfer()
    {
        return Ok(new { Status = "Success" });
    }
}
