using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sentinel.Application.Auth;
using Sentinel.Middleware.Filters;

namespace Sentinel.SampleHost.Controllers;

[ApiController]
[Route("v1/finance")]
public sealed class FinanceController : ControllerBase
{
    [HttpPost("transfer")]
    [Authorize(Policy = Policies.RequireAcr3)]
    [RequireIdempotency]
    [RequireSurgicalAuthorization]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public IActionResult MakeTransfer([FromBody] TransferRequest request)
    {
        return Ok(new { Status = "Success", request.TransactionId });
    }

    public sealed record TransferRequest(
        string TransactionId,
        decimal Amount,
        string Currency,
        string DestinationAccount);
}
