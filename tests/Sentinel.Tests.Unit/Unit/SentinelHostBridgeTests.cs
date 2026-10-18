using Microsoft.Extensions.DependencyInjection;
using Moq;
using Sentinel.AspNetCore.Extensions;
using ApplicationRevocation = Sentinel.Application.Auth.Interfaces.IAuthRevocationService;
using SecurityRevocation = Sentinel.Security.Abstractions.Security.IAuthRevocationService;

namespace Sentinel.Tests.Unit.Unit;

public sealed class SentinelHostBridgeTests
{
    [Fact(DisplayName = "🔴 Revocation bridge fails closed when the IdP reports failure")]
    public async Task RevocationBridge_WhenInnerReturnsFalse_Throws()
    {
        await using var provider = BuildProvider(revoked: false);
        using var scope = provider.CreateScope();
        var bridge = scope.ServiceProvider.GetRequiredService<SecurityRevocation>();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            bridge.RevokeAllSessionsAsync("user-1", TestContext.Current.CancellationToken));
    }

    [Fact(DisplayName = "✅ Revocation bridge completes when the IdP confirms revocation")]
    public async Task RevocationBridge_WhenInnerReturnsTrue_Completes()
    {
        await using var provider = BuildProvider(revoked: true);
        using var scope = provider.CreateScope();
        var bridge = scope.ServiceProvider.GetRequiredService<SecurityRevocation>();

        await bridge.RevokeAllSessionsAsync("user-1", TestContext.Current.CancellationToken);
    }

    [Fact(DisplayName = "✅ Host-provided implementations win over the bridges")]
    public void AddSentinelHostBridges_DoesNotOverrideHostRegistration()
    {
        var hostImpl = Mock.Of<SecurityRevocation>();
        var services = new ServiceCollection();
        services.AddSingleton(hostImpl);

        services.AddSentinelHostBridges();

        using var provider = services.BuildServiceProvider();
        Assert.Same(hostImpl, provider.GetRequiredService<SecurityRevocation>());
    }

    private static ServiceProvider BuildProvider(bool revoked)
    {
        var inner = new Mock<ApplicationRevocation>();
        inner.Setup(x => x.RevokeAllSessionsAsync("user-1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(revoked);

        var services = new ServiceCollection();
        services.AddSingleton(inner.Object);
        services.AddSentinelHostBridges();
        return services.BuildServiceProvider();
    }
}
