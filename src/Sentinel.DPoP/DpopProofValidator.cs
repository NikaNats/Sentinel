using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Options;
using Sentinel.DPoP.Pqc;
using Sentinel.Security.Abstractions.Options;
using Sentinel.Security.Abstractions.Pqc;
using MlDsaSecurityKey = Sentinel.Security.Abstractions.Pqc.MlDsaSecurityKey;

namespace Sentinel.DPoP;

public sealed class DpopProofValidator : IDpopProofValidator
{
    private const int MaxDpopHeaderLength = 8192;
    private static readonly JsonWebTokenHandler TokenHandler = new();

    private static readonly HashSet<string> GloballyAllowedAlgorithms = new(StringComparer.OrdinalIgnoreCase)
    {
        "PS256", "ES256", "EdDSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
    };

    private readonly DPoPOptions _options;
    private readonly PqcCryptoProviderFactory _pqcFactory;
    private readonly IJtiReplayCache _replayCache;
    private readonly HashSet<string> _supportedAlgorithms;
    private readonly IDpopThumbprintComputer _thumbprintComputer;
    private readonly TimeProvider _timeProvider;

    public DpopProofValidator(
        IJtiReplayCache replayCache,
        IOptions<DPoPOptions> options,
        IDpopThumbprintComputer? thumbprintComputer = null,
        TimeProvider? timeProvider = null,
        IMlDsaSignatureVerifier? mlDsaVerifier = null)
    {
        _replayCache = replayCache ?? throw new ArgumentNullException(nameof(replayCache));
        _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
        _thumbprintComputer = thumbprintComputer ?? new DpopThumbprintComputer();
        _timeProvider = timeProvider ?? TimeProvider.System;

        if (_options.AllowedAlgorithms == null || _options.AllowedAlgorithms.Length == 0)
        {
            throw new CryptographicException("FAPI 2.0 violation: AllowedAlgorithms list cannot be empty.");
        }

        foreach (var alg in _options.AllowedAlgorithms)
        {
            if (!GloballyAllowedAlgorithms.Contains(alg))
            {
                throw new CryptographicException(
                    $"FAPI 2.0 violation: Prohibited algorithm '{alg}' found in configuration.");
            }
        }

        _supportedAlgorithms = new HashSet<string>(_options.AllowedAlgorithms, StringComparer.OrdinalIgnoreCase);
        var verifier = mlDsaVerifier ?? new FailClosedMlDsaVerifier();
        _pqcFactory = new PqcCryptoProviderFactory(verifier);
    }

    public async Task<SecurityResult<DpopValidationSuccess>> ValidateAsync(
        DpopValidationRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request == null)
        {
            return SecurityResultFactory.Failure<DpopValidationSuccess>("invalid_request");
        }

        if (string.IsNullOrWhiteSpace(request.DpopHeader) || request.DpopHeader.Length > MaxDpopHeaderLength)
        {
            return SecurityResultFactory.Failure<DpopValidationSuccess>("invalid_dpop_header_size");
        }

        try
        {
            if (!TokenHandler.CanReadToken(request.DpopHeader))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("invalid_dpop");
            }

            var dpopToken = TokenHandler.ReadJsonWebToken(request.DpopHeader);

            if (!IsSupportedAlgorithm(dpopToken.Alg))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("unsupported_algorithm");
            }

            if (!string.Equals(dpopToken.Typ, "dpop+jwt", StringComparison.OrdinalIgnoreCase))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("invalid_typ");
            }

            if (!dpopToken.TryGetHeaderValue<JsonElement>("jwk", out var jwkElement))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("missing_jwk");
            }

            if (jwkElement.TryGetProperty("alg", out var jwkAlgProp))
            {
                var jwkAlg = jwkAlgProp.GetString();
                if (!string.Equals(jwkAlg, dpopToken.Alg, StringComparison.OrdinalIgnoreCase))
                {
                    return SecurityResultFactory.Failure<DpopValidationSuccess>("unsupported_algorithm");
                }
            }

            if (jwkElement.TryGetProperty("d", out _) ||
                jwkElement.TryGetProperty("k", out _) ||
                jwkElement.TryGetProperty("p", out _) ||
                jwkElement.TryGetProperty("q", out _))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("private_jwk_rejected");
            }

            if (!jwkElement.TryGetProperty("kty", out var ktyProp))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("invalid_jwk");
            }

            var kty = ktyProp.GetString();
            var alg = dpopToken.Alg;

            var isMatched = kty switch
            {
                "EC" => alg.StartsWith("ES", StringComparison.Ordinal),
                "RSA" => alg.StartsWith("PS", StringComparison.Ordinal),
                "OKP" => string.Equals(alg, "EdDSA", StringComparison.Ordinal),
                "ML-DSA" => alg.StartsWith("ML-DSA", StringComparison.Ordinal),
                _ => false
            };

            if (!isMatched)
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("unsupported_algorithm");
            }

            SecurityKey signingKey;
            if (string.Equals(kty, "ML-DSA", StringComparison.Ordinal))
            {
                if (!jwkElement.TryGetProperty("x", out var xProp) || string.IsNullOrWhiteSpace(xProp.GetString()))
                {
                    return SecurityResultFactory.Failure<DpopValidationSuccess>("invalid_jwk");
                }

                var publicKeyBytes = Base64UrlEncoder.DecodeBytes(xProp.GetString());

                if (!IsValidMlDsaKeySize(alg, publicKeyBytes.Length))
                {
                    return SecurityResultFactory.Failure<DpopValidationSuccess>("invalid_jwk");
                }

                signingKey = new MlDsaSecurityKey(publicKeyBytes, alg);
            }
            else
            {
                var jwkRawText = jwkElement.GetRawText();
                if (string.IsNullOrWhiteSpace(jwkRawText))
                {
                    return SecurityResultFactory.Failure<DpopValidationSuccess>("invalid_jwk");
                }

                signingKey = JsonWebKey.Create(jwkRawText);
            }

            if (!await ValidateDpopSignatureAsync(request.DpopHeader, signingKey, alg, cancellationToken)
                    .ConfigureAwait(false))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("invalid_signature");
            }

            if (!dpopToken.TryGetPayloadValue<string>("jti", out var jti) || string.IsNullOrWhiteSpace(jti))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("missing_jti");
            }

            if (!dpopToken.TryGetPayloadValue<string>("htm", out var htm)
                || !string.Equals(htm, request.HttpMethod,
                    StringComparison.OrdinalIgnoreCase)) // RFC 9449: case-insensitive matching
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("htm_mismatch");
            }

            if (!dpopToken.TryGetPayloadValue<string>("htu", out var htu))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("htu_mismatch");
            }

            if (!TryNormalizeUri(htu, out var normalizedHtu) ||
                !TryNormalizeUri(request.HttpUri.AbsoluteUri, out var normalizedRequestUri) ||
                !string.Equals(normalizedHtu, normalizedRequestUri, StringComparison.Ordinal))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("htu_mismatch");
            }

            if (!dpopToken.TryGetPayloadValue<string>("nonce", out var proofNonce))
            {
                proofNonce = string.Empty;
            }

            var nonceInProofExists = !string.IsNullOrWhiteSpace(proofNonce);

            if (_options.RequireNonce)
            {
                if (!nonceInProofExists)
                {
                    return SecurityResultFactory.Failure<DpopValidationSuccess>("use_dpop_nonce");
                }

                if (string.IsNullOrWhiteSpace(request.ExpectedNonce))
                {
                    return SecurityResultFactory.Failure<DpopValidationSuccess>("use_dpop_nonce");
                }

                if (!string.Equals(proofNonce, request.ExpectedNonce, StringComparison.Ordinal))
                {
                    return SecurityResultFactory.Failure<DpopValidationSuccess>("use_dpop_nonce");
                }
            }
            else if (!string.IsNullOrWhiteSpace(request.ExpectedNonce))
            {
                if (!nonceInProofExists || !string.Equals(proofNonce, request.ExpectedNonce, StringComparison.Ordinal))
                {
                    return SecurityResultFactory.Failure<DpopValidationSuccess>("use_dpop_nonce");
                }
            }

            if (!dpopToken.TryGetPayloadValue<long>("iat", out var iat))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("missing_iat");
            }

            var iatTime = DateTimeOffset.FromUnixTimeSeconds(iat);
            var now = _timeProvider.GetUtcNow();
            var skew = TimeSpan.FromSeconds(_options.AllowedClockSkewSeconds);

            if (iatTime < now.AddSeconds(-_options.ProofLifetimeSeconds).Subtract(skew) ||
                iatTime > now.Add(skew))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("iat_out_of_bounds");
            }

            var thumbprint = _thumbprintComputer.Compute(jwkElement);
            if (string.IsNullOrEmpty(thumbprint))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("unsupported_key_type");
            }

            if (!string.IsNullOrEmpty(request.AccessToken))
            {
                if (!TokenHandler.CanReadToken(request.AccessToken))
                {
                    return SecurityResultFactory.Failure<DpopValidationSuccess>("invalid_access_token");
                }

                var accessJwt = TokenHandler.ReadJsonWebToken(request.AccessToken);
                if (!accessJwt.TryGetPayloadValue<JsonElement>("cnf", out var cnf)
                    || !cnf.TryGetProperty("jkt", out var jktElement)
                    || string.IsNullOrWhiteSpace(jktElement.GetString()))
                {
                    return SecurityResultFactory.Failure<DpopValidationSuccess>("missing_cnf_jkt");
                }

                if (!string.Equals(jktElement.GetString(), thumbprint, StringComparison.Ordinal))
                {
                    return SecurityResultFactory.Failure<DpopValidationSuccess>("jkt_mismatch");
                }
            }

            var cacheExpiration = iatTime.AddSeconds(_options.ProofLifetimeSeconds).Add(skew);

            var stored = await _replayCache.TryMarkUsedAsync(
                $"dpop:{jti}",
                cacheExpiration,
                cancellationToken).ConfigureAwait(false);

            if (!stored)
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("jti_replay_detected");
            }

            var newNonce = GenerateNewNonce();
            var success = new DpopValidationSuccess(newNonce, thumbprint);
            return SecurityResultFactory.Create(success);
        }
        catch (Exception ex) when (ex is JsonException or SecurityTokenException or CryptographicException
                                       or FormatException or ArgumentException or InvalidOperationException)
        {
            return SecurityResultFactory.Failure<DpopValidationSuccess>("validation_error");
        }
    }

    private async Task<bool> ValidateDpopSignatureAsync(
        string token,
        SecurityKey signingKey,
        string algorithm,
        CancellationToken cancellationToken)
    {
        const bool validateLifetime = false;

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signingKey,
            ValidateIssuer = false,
            ValidateAudience = false,
            RequireSignedTokens = true,
            ValidAlgorithms = [algorithm],
            ValidateLifetime = validateLifetime,
            RequireExpirationTime = validateLifetime,
            CryptoProviderFactory = _pqcFactory
        };

        var validationResult = await TokenHandler.ValidateTokenAsync(token, validationParameters).ConfigureAwait(false);
        return validationResult.IsValid;
    }

    private static bool TryNormalizeUri(string uri, [NotNullWhen(true)] out string? normalizedUri)
    {
        normalizedUri = null;
        if (string.IsNullOrWhiteSpace(uri))
        {
            return false;
        }

        try
        {
            var parsed = new Uri(uri, UriKind.Absolute);
            var builder = new UriBuilder(parsed)
            {
                Query = string.Empty,
                Fragment = string.Empty
            };

            if (parsed.IsDefaultPort)
            {
                builder.Port = -1;
            }

            normalizedUri = builder.Uri.AbsoluteUri.TrimEnd('/');
            return true;
        }
        catch (UriFormatException)
        {
            return false;
        }
    }

    private static bool IsValidMlDsaKeySize(string algorithm, int sizeInBytes) =>
        algorithm switch
        {
            "ML-DSA-44" => sizeInBytes == 1312,
            "ML-DSA-65" => sizeInBytes == 1952,
            "ML-DSA-87" => sizeInBytes == 2592,
            _ => false
        };

    private static string GenerateNewNonce()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncoder.Encode(bytes);
    }

    private bool IsSupportedAlgorithm(string? algorithm) =>
        !string.IsNullOrWhiteSpace(algorithm)
        && _supportedAlgorithms.Contains(algorithm);

    private sealed class FailClosedMlDsaVerifier : IMlDsaSignatureVerifier
    {
        public bool Verify(string algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> input,
            ReadOnlySpan<byte> signature) => false;
    }
}
