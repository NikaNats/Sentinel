using Microsoft.Extensions.Options;
using Sentinel.Security.Abstractions.Options;

namespace Sentinel.DPoP;

/// <summary>
///     Validates RFC 9449 DPoP proofs with FAPI 2.0 security requirements.
/// </summary>
internal sealed class DpopProofValidator : IDpopProofValidator
{
    private static readonly JsonWebTokenHandler TokenHandler = new();
    private readonly DPoPOptions _options;
    private readonly IJtiReplayCache _replayCache;
    private readonly HashSet<string> _supportedAlgorithms;
    private readonly IDpopThumbprintComputer _thumbprintComputer;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    ///     Initializes a new instance of the <see cref="DpopProofValidator" /> class.
    /// </summary>
    /// <remarks>
    ///     ✅ FIX: Injects IOptions&lt;DPoPOptions&gt; for configuration-driven security values
    ///     and case-insensitive algorithm matching.
    /// </remarks>
    /// <param name="replayCache">Cache for preventing JTI replay attacks.</param>
    /// <param name="options">Configuration for DPoP validation settings.</param>
    /// <param name="thumbprintComputer">Computes RFC 7638 thumbprints (optional, creates default if null).</param>
    /// <param name="timeProvider">Time provider for validation (optional, defaults to system time).</param>
    public DpopProofValidator(
        IJtiReplayCache replayCache,
        IOptions<DPoPOptions> options,
        IDpopThumbprintComputer? thumbprintComputer = null,
        TimeProvider? timeProvider = null)
    {
        _replayCache = replayCache ?? throw new ArgumentNullException(nameof(replayCache));
        _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
        _thumbprintComputer = thumbprintComputer ?? new DpopThumbprintComputer();
        _timeProvider = timeProvider ?? TimeProvider.System;

        // ✅ FIX: Case-insensitive algorithm matching (handles "ES256" vs "es256")
        _supportedAlgorithms = new HashSet<string>(_options.AllowedAlgorithms, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    ///     Validates a DPoP proof and returns cryptographic binding information per RFC 9449.
    /// </summary>
    /// <param name="request">Validation context including proof, HTTP method/URI, and optional nonce.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    ///     Success with nonce and thumbprint on valid proof.
    ///     Failure if proof is malformed, replayed, misbound, or timestamp-invalid.
    /// </returns>
    public async Task<SecurityResult<DpopValidationSuccess>> ValidateAsync(
        DpopValidationRequest request,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Parse JWT and verify structure
            if (!TokenHandler.CanReadToken(request.DpopHeader))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("invalid_dpop");
            }

            var dpopToken = TokenHandler.ReadJsonWebToken(request.DpopHeader);

            // Validate algorithm (case-insensitive via configured set)
            if (!IsSupportedAlgorithm(dpopToken.Alg))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("unsupported_algorithm");
            }

            // Validate typ header
            if (!string.Equals(dpopToken.Typ, "dpop+jwt", StringComparison.OrdinalIgnoreCase))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("invalid_typ");
            }

            // ✅ FIX: Request JsonElement directly to prevent .ToString() type-name leakage
            if (!dpopToken.TryGetHeaderValue<JsonElement>("jwk", out var jwkElement))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("missing_jwk");
            }

            var jwkJson = jwkElement.GetRawText();
            if (string.IsNullOrWhiteSpace(jwkJson))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("invalid_jwk");
            }

            // Reject private keys
            if (jwkElement.TryGetProperty("d", out _))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("private_jwk_rejected");
            }

            // Validate JWT signature using extracted JWK
            if (!await ValidateDpopSignatureAsync(request.DpopHeader, jwkJson, dpopToken.Alg, cancellationToken))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("invalid_signature");
            }

            // Validate JTI (prevent replay)
            if (!dpopToken.TryGetPayloadValue<string>("jti", out var jti) || string.IsNullOrWhiteSpace(jti))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("missing_jti");
            }

            // ✅ FIX: RFC 9449 §4.2 - HTTP Method must be exact case (Ordinal, not OrdinalIgnoreCase)
            if (!dpopToken.TryGetPayloadValue<string>("htm", out var htm)
                || !string.Equals(htm, request.HttpMethod, StringComparison.Ordinal))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("htm_mismatch");
            }

            // Validate HTTP URL binding
            if (!dpopToken.TryGetPayloadValue<string>("htu", out var htu)
                || !string.Equals(NormalizeUri(htu), NormalizeUri(request.HttpUri.AbsoluteUri),
                    StringComparison.Ordinal))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("htu_mismatch");
            }

            // Validate issued-at timestamp (RFC 9449 requires iat-based freshness, not exp)
            if (!dpopToken.TryGetPayloadValue<long>("iat", out var iat))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("missing_iat");
            }

            // ✅ FIX: Configuration-driven clock skew instead of hardcoded magic numbers
            var iatTime = DateTimeOffset.FromUnixTimeSeconds(iat);
            var now = _timeProvider.GetUtcNow();
            var skew = TimeSpan.FromSeconds(_options.AllowedClockSkewSeconds);

            // Proof must be issued recently. Window: [Now - ProofLifetime - Skew, Now + Skew]
            if (iatTime < now.AddSeconds(-_options.ProofLifetimeSeconds).Subtract(skew) ||
                iatTime > now.Add(skew))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("iat_out_of_bounds");
            }

            // Validate nonce if provided
            if (!string.IsNullOrWhiteSpace(request.ExpectedNonce))
            {
                if (!dpopToken.TryGetPayloadValue<string>("nonce", out var proofNonce)
                    || !string.Equals(proofNonce, request.ExpectedNonce, StringComparison.Ordinal))
                {
                    return SecurityResultFactory.Failure<DpopValidationSuccess>("nonce_mismatch");
                }
            }

            // Compute thumbprint for cryptographic binding
            var thumbprint = _thumbprintComputer.Compute(jwkElement);
            if (string.IsNullOrEmpty(thumbprint))
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("unsupported_key_type");
            }

            // Validate access token binding if provided
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

            // ✅ FIX: Configuration-driven JTI replay TTL instead of hardcoded 120 seconds
            var stored = await _replayCache.TryMarkUsedAsync(
                $"dpop:{jti}",
                now.AddSeconds(_options.ProofLifetimeSeconds),
                cancellationToken);

            if (!stored)
            {
                return SecurityResultFactory.Failure<DpopValidationSuccess>("jti_replay_detected");
            }

            // Success: return nonce for next challenge and thumbprint for binding
            var newNonce = GenerateNewNonce();
            var success = new DpopValidationSuccess(newNonce, thumbprint);
            return SecurityResultFactory.Create(success);
        }
        catch (OperationCanceledException)
        {
            throw;
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

    /// <summary>
    ///     ✅ FIX: Static method since it only uses TokenHandler (static) and parameters.
    ///     Validates JWT signature using the provided keys and algorithm per RFC 7518.
    /// </summary>
    /// <remarks>
    ///     ⚠️ ARCHITECTURE WARNING: ML-DSA Support
    ///     If ML-DSA (MLDSA44/65/87) is requested, Microsoft.IdentityModel requires a registered ICryptoProvider
    ///     that implements the post-quantum cryptography math. If absent, ValidateTokenAsync returns IsValid=false silently.
    ///     Consider logging if an ML-DSA request fails without a registered provider.
    /// </remarks>
    private static async Task<bool> ValidateDpopSignatureAsync(
        string token,
        string jwkJson,
        string algorithm,
        CancellationToken cancellationToken)
    {
        JsonWebKey signingKey;

        try
        {
            signingKey = JsonWebKey.Create(jwkJson);
        }
#pragma warning disable CA1031 // Catch Exception: Malformed JWK must fail validation without throwing
        catch
        {
            return false;
        }
#pragma warning restore CA1031

        // RFC 9449: DPoP proofs don't use exp; freshness is via iat window + nonce
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
            RequireExpirationTime = validateLifetime
        };

        var validationResult = await TokenHandler.ValidateTokenAsync(token, validationParameters);
        return validationResult.IsValid;
    }

    /// <summary>
    ///     Normalizes a URI by removing query string and fragment per RFC 9449.
    /// </summary>
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
#pragma warning disable CA1031 // Catch-all needed: malformed input must fail closed without throwing
        catch (UriFormatException)
        {
            return string.Empty;
        }
#pragma warning restore CA1031
    }

    /// <summary>
    ///     Generates a cryptographically secure random nonce for the next challenge.
    /// </summary>
    private static string GenerateNewNonce()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncoder.Encode(bytes);
    }

    /// <summary>
    ///     Checks if an algorithm is in the supported list for DPoP signatures.
    ///     Uses case-insensitive matching to handle variant capitalizations.
    /// </summary>
    private bool IsSupportedAlgorithm(string? algorithm) =>
        !string.IsNullOrWhiteSpace(algorithm)
        && _supportedAlgorithms.Contains(algorithm);
}
