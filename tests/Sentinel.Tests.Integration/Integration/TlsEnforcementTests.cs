using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FluentAssertions;

namespace Sentinel.Tests.Integration;

[Collection("Sentinel Real Keycloak Integration")]
public sealed class TlsEnforcementTests(RealKeycloakApiFactory factory)
{
    private static readonly TimeSpan SecurityGateTimeout = TimeSpan.FromSeconds(10);

    [Fact(DisplayName = "P0 Security Gate: Keycloak rejects TLS 1.2 downgrades")]
    public async Task Keycloak_WhenAttemptingTls12_MustRejectConnection()
    {
        var act = () => OpenTlsConnectionAsync(SslProtocols.Tls12);

        var exception = await Assert.ThrowsAnyAsync<Exception>(act);

        exception.Should().BeAssignableTo<AuthenticationException>(
            "the server must refuse TLS 1.2 handshakes at the TLS boundary");
    }

    [Fact(DisplayName = "P0 Security Gate: Keycloak accepts TLS 1.3")]
    public async Task Keycloak_WhenUsingTls13_MustAcceptConnection()
    {
        await using var ssl = await OpenTlsConnectionAsync(SslProtocols.Tls13);

        ssl.IsAuthenticated.Should().BeTrue("TLS 1.3 connections must be allowed");
        ssl.SslProtocol.Should().Be(SslProtocols.Tls13);
    }

    [Fact(DisplayName = "P0 Security Gate: Plain HTTP requests must fail")]
    public async Task Keycloak_WhenUsingPlainHttp_MustFail()
    {
        using var timeout = new CancellationTokenSource(SecurityGateTimeout);
        using var client = new TcpClient();

        await client.ConnectAsync(factory.KeycloakHost, factory.KeycloakHttpsMappedPort, timeout.Token);

        await using var stream = client.GetStream();
        var request = Encoding.ASCII.GetBytes(
            $"GET /.well-known/openid-configuration HTTP/1.1\r\nHost: {factory.KeycloakHost}\r\nConnection: close\r\n\r\n");

        await stream.WriteAsync(request, timeout.Token);

        var buffer = new byte[16];
        var bytesRead = await ReadPlainHttpProbeAsync(stream, buffer, timeout.Token);

        if (bytesRead > 0)
        {
            var responsePrefix = Encoding.ASCII.GetString(buffer, 0, bytesRead);
            responsePrefix.Should().NotStartWith("HTTP/",
                "plain HTTP must not receive a valid HTTP response from the HTTPS listener");
        }
    }

    private async Task<SslStream> OpenTlsConnectionAsync(SslProtocols protocol)
    {
        using var timeout = new CancellationTokenSource(SecurityGateTimeout);
#pragma warning disable CA2000
        var client = new TcpClient();
#pragma warning restore CA2000

        try
        {
            await client.ConnectAsync(factory.KeycloakHost, factory.KeycloakHttpsMappedPort, timeout.Token);

            var ssl = new SslStream(
                client.GetStream(),
                false,
                ValidateServerCertificate);

            var options = new SslClientAuthenticationOptions
            {
                TargetHost = factory.KeycloakHost,
                EnabledSslProtocols = protocol,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            };

            await ssl.AuthenticateAsClientAsync(options, timeout.Token);
            return ssl;
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    private bool ValidateServerCertificate(
        object sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        _ = sender;
        _ = chain;
        _ = sslPolicyErrors;

        return certificate is not null && factory.IsExpectedKeycloakCertificate(certificate);
    }

    private static async Task<int> ReadPlainHttpProbeAsync(
        NetworkStream stream,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        try
        {
            return await stream.ReadAsync(buffer, cancellationToken);
        }
        catch (IOException)
        {
            return 0;
        }
        catch (SocketException)
        {
            return 0;
        }
        catch (AuthenticationException)
        {
            return 0;
        }
    }
}
