using Sentinel.Tests.Integration.Fixtures;
using System.Net;

namespace Sentinel.Tests.Integration;

[Collection("Sentinel Integration")]
public sealed class AuthFlowIntegrationTests(SentinelApiFactory factory)
{
    private readonly HttpClient client = factory.CreateClient();

    [Fact(Skip = "Requires Docker-backed Keycloak/Redis integration environment.")]
    public async Task ProtectedEndpoint_WithoutToken_Returns401()
    {
        var response = await client.GetAsync("/v1/Profile");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact(Skip = "Requires seeded Keycloak user, PAR code flow automation, and confidential client assertion plumbing.")]
    public async Task FullFapi2Flow_WithDpop_ReturnsProfile()
    {
        var response = await client.GetAsync("/v1/Profile");

        response.EnsureSuccessStatusCode();
    }
}
