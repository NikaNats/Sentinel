using Microsoft.Extensions.Options;
using Sentinel.DPoP.Pqc;
using Sentinel.Security.Abstractions.Options;
using Sentinel.Security.Abstractions.Pqc;
using MlDsaSecurityKey = Sentinel.Security.Abstractions.Pqc.MlDsaSecurityKey;

namespace Sentinel.DPoP;

/// <summary>
///     Validates RFC 9449 DPoP proofs with FAPI 2.0 security requirements.
/// </summary>
internal sealed class DpopProofValidator : IDpopProofValidator
{
    private static readonly JsonWebTokenHandler TokenHandler = new();
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

        _supportedAlgorithms = new HashSet<string>(_options.AllowedAlgorithms, StringComparer.OrdinalIgnoreCase);

        var verifier = mlDsaVerifier ?? new FailClosedMlDsaVerifier();
        _pqcFactory = new PqcCryptoProviderFactory(verifier);
    }

    public async Task<SecurityResult<DpopValidationSuccess>> ValidateAsync(
        DpopValidationRequest request,
        CancellationToken cancellationToken = default)
    {
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

            var jwkJson = jwkElement.GetRawText();
            if (string.IsNullOrWhiteSpace(jwkJson))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("invalid_jwk");
            }

            if (jwkElement.TryGetProperty("d", out _))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("private_jwk_rejected");
            }

            if (!await ValidateDpopSignatureAsync(request.DpopHeader, jwkJson, dpopToken.Alg, cancellationToken)
                    .ConfigureAwait(false))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("invalid_signature");
            }

            if (!dpopToken.TryGetPayloadValue<string>("jti", out var jti) || string.IsNullOrWhiteSpace(jti))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("missing_jti");
            }

            if (!dpopToken.TryGetPayloadValue<string>("htm", out var htm)
                || !string.Equals(htm, request.HttpMethod, StringComparison.Ordinal))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("htm_mismatch");
            }

            if (!dpopToken.TryGetPayloadValue<string>("htu", out var htu)
                || !string.Equals(NormalizeUri(htu), NormalizeUri(request.HttpUri.AbsoluteUri),
                    StringComparison.Ordinal))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("htu_mismatch");
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

            if (!string.IsNullOrWhiteSpace(request.ExpectedNonce))
            {
                if (!dpopToken.TryGetPayloadValue<string>("nonce", out var proofNonce)
                    || !string.Equals(proofNonce, request.ExpectedNonce, StringComparison.Ordinal))
                {
                    return SecurityResultFactory.Failure<DpopValidationSuccess>("nonce_mismatch");
                }
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

            var stored = await _replayCache.TryMarkUsedAsync(
                $"dpop:{jti}",
                now.AddSeconds(_options.ProofLifetimeSeconds),
                cancellationToken).ConfigureAwait(false);

            if (!stored)
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("jti_replay_detected");
            }

            var newNonce = GenerateNewNonce();
            var success = new DpopValidationSuccess(newNonce, thumbprint);
            return SecurityResultFactory.Create(success);
        }
        catch (JsonException)
        {
            return SecurityResultFactory.Failure<DpopValidationSuccess>("validation_error");
        }
        catch (SecurityTokenException)
        {
            return SecurityResultFactory.Failure<DpopValidationSuccess>("validation_error");
        }
        catch (CryptographicException)
        {
            return SecurityResultFactory.Failure<DpopValidationSuccess>("validation_error");
        }
        catch (FormatException)
        {
            return SecurityResultFactory.Failure<DpopValidationSuccess>("validation_error");
        }
        catch (ArgumentException)
        {
            return SecurityResultFactory.Failure<DpopValidationSuccess>("validation_error");
        }
        catch (InvalidOperationException)
        {
            return SecurityResultFactory.Failure<DpopValidationSuccess>("validation_error");
        }
    }

    private async Task<bool> ValidateDpopSignatureAsync(
        string token,
        string jwkJson,
        string algorithm,
        CancellationToken cancellationToken)
    {
        SecurityKey signingKey;

        try
        {
            using var jwkDoc = JsonDocument.Parse(jwkJson);
            var root = jwkDoc.RootElement;

            if (root.TryGetProperty("kty", out var kty) &&
                string.Equals(kty.GetString(), "ML-DSA", StringComparison.Ordinal))
            {
                if (!root.TryGetProperty("x", out var xProp) || string.IsNullOrWhiteSpace(xProp.GetString()))
                {
                    return false;
                }

                var publicKeyBytes = Base64UrlEncoder.DecodeBytes(xProp.GetString());
                signingKey = new MlDsaSecurityKey(publicKeyBytes, algorithm);
            }
            else
            {
                signingKey = JsonWebKey.Create(jwkJson);
            }
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException or FormatException)
        {
            return false;
        }

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

    private static string NormalizeUri(string uri)
    {
        try
        {
            var parsed = new Uri(uri, UriKind.Absolute);
            var builder = new UriBuilder(parsed)
            {
                Query = string.Empty,
                Fragment = string.Empty
            };

            return builder.Uri.AbsoluteUri.TrimEnd('/');
        }
        catch (UriFormatException)
        {
            return string.Empty;
        }
    }

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
