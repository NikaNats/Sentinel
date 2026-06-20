using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Sentinel.AspNetCore.Infrastructure;

/// <summary>
/// Provides high-security HTTP Handlers with Custom Root Trust support
/// </summary>
public static class SecureHttpHandlerFactory
{
    public static SocketsHttpHandler Create(string? trustedRootCaFilePath, bool isDevelopment)
    {
        var handler = new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls13,
                CertificateRevocationCheckMode = isDevelopment ? X509RevocationMode.NoCheck : X509RevocationMode.Online
            }
        };

        if (!string.IsNullOrWhiteSpace(trustedRootCaFilePath) && File.Exists(trustedRootCaFilePath))
        {
            var pemContent = File.ReadAllText(trustedRootCaFilePath);

            handler.SslOptions.RemoteCertificateValidationCallback = (sender, cert, chain, errors) =>
            {
                if (errors == SslPolicyErrors.None) return true;

                using var trustedCa = X509Certificate2.CreateFromPem(pemContent);
                using var customChain = new X509Chain();

                customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                customChain.ChainPolicy.DisableCertificateDownloads = true;
                customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                customChain.ChainPolicy.CustomTrustStore.Add(trustedCa);

                var certificate = (X509Certificate2)cert!;
                return customChain.Build(certificate);
            };
        }

        return handler;
    }
}
