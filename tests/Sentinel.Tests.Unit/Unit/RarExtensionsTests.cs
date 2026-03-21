using System.Security.Claims;
using Sentinel.Application.Auth.Rar;

namespace Sentinel.Tests.Unit;

public sealed class RarExtensionsTests
{
    [Fact]
    public void GetAuthorizationDetails_WhenClaimMissing_ReturnsEmpty()
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity());

        var details = user.GetAuthorizationDetails();

        Assert.Empty(details);
    }

    [Fact]
    public void GetAuthorizationDetails_WhenClaimInvalidJson_ReturnsEmpty()
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim("authorization_details", "not-json")], "test"));

        var details = user.GetAuthorizationDetails();

        Assert.Empty(details);
    }

    [Fact]
    public void GetAuthorizationDetails_WhenClaimValid_ReturnsParsedDetails()
    {
        const string json = """
            [{"type":"urn:sentinel:finance:transfer","transaction_id":"txn-123","amount":50.00,"currency":"GEL"}]
            """;
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim("authorization_details", json)], "test"));

        var details = user.GetAuthorizationDetails();

        Assert.Single(details);
        Assert.Equal("urn:sentinel:finance:transfer", details[0].Type);
        Assert.Equal("txn-123", details[0].TransactionId);
        Assert.Equal(50.00m, details[0].Amount);
        Assert.Equal("GEL", details[0].Currency);
    }
}
