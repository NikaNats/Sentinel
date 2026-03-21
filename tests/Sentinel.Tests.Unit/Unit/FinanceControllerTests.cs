using System.Reflection;
using Microsoft.AspNetCore.Mvc;
using Sentinel.Controllers;
using Sentinel.Middleware.Filters;

namespace Sentinel.Tests.Unit;

public sealed class FinanceControllerTests
{
    [Fact]
    public void MakeTransfer_WhenCalled_ReturnsOkWithTransactionId()
    {
        var controller = new FinanceController();
        var request = new FinanceController.TransferRequest("txn-55", 55m, "GEL", "dest-1");

        var result = controller.MakeTransfer(request);

        var ok = Assert.IsType<OkObjectResult>(result);
        var valueType = ok.Value?.GetType();
        Assert.NotNull(valueType);
        var statusValue = valueType!.GetProperty("Status", BindingFlags.Public | BindingFlags.Instance)
            ?.GetValue(ok.Value);
        var transactionIdValue = valueType.GetProperty("TransactionId", BindingFlags.Public | BindingFlags.Instance)
            ?.GetValue(ok.Value);
        Assert.Equal("Success", statusValue?.ToString());
        Assert.Equal("txn-55", transactionIdValue?.ToString());
    }

    [Fact]
    public void MakeTransfer_HasRequireSurgicalAuthorizationAttribute()
    {
        var method = typeof(FinanceController).GetMethod(nameof(FinanceController.MakeTransfer));

        Assert.NotNull(method);
        var attribute = method!.GetCustomAttributes(typeof(RequireSurgicalAuthorizationAttribute), true);
        Assert.Single(attribute);
    }
}
