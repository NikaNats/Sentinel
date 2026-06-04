using System.Net.Http;
using System.Net.Security;
using System.Security.Authentication;
using FluentAssertions;

namespace Sentinel.Tests.Integration;

[Collection("Sentinel Real Keycloak Integration")]
public sealed class TlsEnforcementTests(RealKeycloakApiFactory factory)
{
    [Fact(DisplayName = "P0 Security Gate: Keycloak rejects TLS 1.2 downgrades")]
    public async Task Keycloak_WhenAttemptingTls12_MustRejectConnection()
    {
        var handler = new SocketsHttpHandler
        {
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12,
                RemoteCertificateValidationCallback = (_, _, _, _) => true
            }
        };

        using var attackerClient = new HttpClient(handler);
        var metadataUrl = $"{factory.Authority}/.well-known/openid-configuration";

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() =>
            attackerClient.GetAsync(metadataUrl));

        exception.InnerException.Should().BeOfType<AuthenticationException>(
            "the server must refuse TLS 1.2 handshakes");
    }

    [Fact(DisplayName = "P0 Security Gate: Keycloak accepts TLS 1.3")]
    public async Task Keycloak_WhenUsingTls13_MustAcceptConnection()
    {
        var handler = new SocketsHttpHandler
        {
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls13,
                RemoteCertificateValidationCallback = (_, _, _, _) => true
            }
        };

        using var legitimateClient = new HttpClient(handler);
        var metadataUrl = $"{factory.Authority}/.well-known/openid-configuration";

        using var response = await legitimateClient.GetAsync(metadataUrl);

        response.IsSuccessStatusCode.Should().BeTrue("TLS 1.3 connections must be allowed");
    }

    [Fact(DisplayName = "P0 Security Gate: Plain HTTP requests must fail")]
    public async Task Keycloak_WhenUsingPlainHttp_MustFail()
    {
        using var client = new HttpClient();
        var httpUrl = $"{factory.Authority}/.well-known/openid-configuration"
            .Replace("https://", "http://", StringComparison.OrdinalIgnoreCase);

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.GetAsync(httpUrl));

        exception.Should().NotBeNull("plain HTTP must be blocked at the port boundary");
    }
}
