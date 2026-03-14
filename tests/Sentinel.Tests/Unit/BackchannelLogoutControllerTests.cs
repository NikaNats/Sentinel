using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Controllers;

namespace Sentinel.Tests.Unit;

public sealed class BackchannelLogoutControllerTests
{
    [Fact]
    public async Task Logout_WhenTokenValid_BlacklistsSessionAndReturnsOk()
    {
        var validator = new Mock<ILogoutTokenValidator>();
        validator.Setup(x => x.ValidateAndExtractSessionIdAsync("token", It.IsAny<CancellationToken>()))
            .ReturnsAsync("sid-123");

        var blacklist = new Mock<ISessionBlacklistCache>();
        var configuration = BuildConfiguration();

        var sut = new BackchannelLogoutController(validator.Object, blacklist.Object, configuration, NullLogger<BackchannelLogoutController>.Instance);

        var result = await sut.Logout("token", CancellationToken.None);

        Assert.IsType<OkResult>(result);
        blacklist.Verify(x => x.BlacklistSessionAsync("sid-123", TimeSpan.FromHours(8), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Logout_WhenTokenInvalid_ReturnsBadRequest()
    {
        var validator = new Mock<ILogoutTokenValidator>();
        validator.Setup(x => x.ValidateAndExtractSessionIdAsync("bad", It.IsAny<CancellationToken>()))
            .ReturnsAsync((string?)null);

        var blacklist = new Mock<ISessionBlacklistCache>();
        var configuration = BuildConfiguration();

        var sut = new BackchannelLogoutController(validator.Object, blacklist.Object, configuration, NullLogger<BackchannelLogoutController>.Instance);

        var result = await sut.Logout("bad", CancellationToken.None);

        Assert.IsType<BadRequestResult>(result);
        blacklist.Verify(x => x.BlacklistSessionAsync(It.IsAny<string>(), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    private static IConfiguration BuildConfiguration()
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Keycloak:SsoSessionMaxLifespanSeconds"] = "28800"
            })
            .Build();
    }
}
