namespace Sentinel.AspNetCore.Options
{
    using System.ComponentModel.DataAnnotations;

    /// <summary>
    /// Manages mTLS binding parameters for enterprise environments.
    /// </summary>
    public sealed class MtlsBindingOptions
    {
        public const string SectionName = "Sentinel:Mtls";

        /// <summary>
        /// If enabled, the system will allow direct connections to Kestrel.
        /// </summary>
        public bool AllowDirectConnection { get; init; }

        /// <summary>
        /// Validation filter. Should always be true in production.
        /// Disabled in test environments because test certificates lack a real trust chain.
        /// </summary>
        public bool ValidateChain { get; init; } = true;

        /// <summary>
        /// Priority list of headers where cloud proxies place the client certificate.
        /// </summary>
        public string[] CertificateHeaders { get; init; } =
        [
            "X-Client-Cert",
            "X-SSL-Client-Cert",
            "X-ARR-ClientCert",
            "X-Amzn-Mtls-Client-Cert"
        ];

        /// <summary>
        /// List of trusted Ingress/proxy CIDR ranges.
        /// </summary>
        [Required]
        public string[] TrustedProxies { get; init; } = ["127.0.0.1/32", "::1/128"];
    }
}
