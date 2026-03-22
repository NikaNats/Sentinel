namespace Sentinel.SdJwt;

/// <summary>
/// Processes and verifies Selective Disclosure JWT (SD-JWT) presentations (RFC 9901).
/// Handles format validation, disclosure digest verification, and key binding validation.
/// </summary>
public sealed class SdJwtPresenter
{
    private static readonly JsonWebTokenHandler TokenHandler = new();
    private readonly ISdJwtTokenValidator _tokenValidator;
    private readonly SdJwtVerificationOptions _options;
    private readonly ILogger<SdJwtPresenter> _logger;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a new instance of the SdJwtPresenter.
    /// </summary>
    /// <param name="tokenValidator">Validates issuer and key binding tokens.</param>
    /// <param name="options">Configuration for SD-JWT verification.</param>
    /// <param name="logger">Logger for diagnostic messages.</param>
    /// <param name="timeProvider">Time provider for token age validation (optional).</param>
    public SdJwtPresenter(
        ISdJwtTokenValidator tokenValidator,
        SdJwtVerificationOptions? options = null,
        ILogger<SdJwtPresenter>? logger = null,
        TimeProvider? timeProvider = null)
    {
        _tokenValidator = tokenValidator ?? throw new ArgumentNullException(nameof(tokenValidator));
        _options = options ?? new SdJwtVerificationOptions();
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<SdJwtPresenter>.Instance;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Verifies an SD-JWT presentation with optional key binding.
    /// </summary>
    /// <remarks>
    /// SD-JWT presentation format: issuer_jwt~disclosure1~disclosure2~...~key_binding_jwt
    ///
    /// Verification process:
    /// 1. Parses presentation format (issuer JWT, disclosures, key binding JWT)
    /// 2. Validates issuer token signature and claims
    /// 3. Validates key binding JWT signature, age, and sd_hash
    /// 4. Reconstructs claims from disclosures based on _sd digests
    /// 5. Returns ClaimsPrincipal with disclosed claims
    /// </remarks>
    /// <param name="sdJwtPresentation">Complete SD-JWT presentation string with ~ separators.</param>
    /// <param name="expectedAudience">Expected audience for token validation.</param>
    /// <param name="expectedNonce">Optional nonce to validate in key binding token.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Verification result with principal or error details.</returns>
    public async Task<SdJwtVerificationResult> VerifyPresentationAsync(
        string sdJwtPresentation,
        string expectedAudience,
        string? expectedNonce = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(sdJwtPresentation))
        {
            return SdJwtVerificationResult.Failure("SD-JWT presentation is required.");
        }

        var parts = sdJwtPresentation.Split('~');
        if (parts.Length < 2)
        {
            return SdJwtVerificationResult.Failure("Invalid SD-JWT presentation format (missing ~ separator).");
        }

        var issuerJwt = parts[0];
        var kbJwt = parts[^1];
        var disclosures = parts.Length > 2 ? parts[1..^1] : [];

        if (string.IsNullOrWhiteSpace(issuerJwt))
        {
            return SdJwtVerificationResult.Failure("Issuer JWT is missing.");
        }

        if (string.IsNullOrWhiteSpace(kbJwt))
        {
            return SdJwtVerificationResult.Failure("Key binding JWT is missing.");
        }

        try
        {
            // Validate issuer token
            var issuerValidation = await _tokenValidator.ValidateIssuerTokenAsync(
                issuerJwt, expectedAudience, cancellationToken);

            if (!issuerValidation.IsValid || issuerValidation.Token is null)
            {
                _logger.LogWarning("SD-JWT issuer token validation failed: {Error}", issuerValidation.Error);
                return SdJwtVerificationResult.Failure(issuerValidation.Error ?? "Issuer token validation failed.");
            }

            var issuerToken = issuerValidation.Token;

            // Validate key binding JWT
            var keyBindingError = await ValidateKeyBindingAsync(
                kbJwt, issuerToken, issuerJwt, disclosures, expectedAudience, expectedNonce, cancellationToken);

            if (keyBindingError is not null)
            {
                _logger.LogWarning("SD-JWT key binding validation failed: {Error}", keyBindingError);
                return SdJwtVerificationResult.Failure(keyBindingError);
            }

            // Reconstruct claims from disclosures
            var result = ReconstructClaims(issuerToken, disclosures);
            return result;
        }
        catch (OperationCanceledException)
        {
            return SdJwtVerificationResult.Failure("SD-JWT verification was cancelled.");
        }
#pragma warning disable CA1031  // Recover from all exceptions
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during SD-JWT verification");
            return SdJwtVerificationResult.Failure("SD-JWT verification failed due to an internal error.");
        }
#pragma warning restore CA1031
    }

    /// <summary>
    /// Validates the key binding JWT and verifies sd_hash.
    /// </summary>
    /// <returns>Error message if validation fails, null if validation succeeds.</returns>
    private async Task<string?> ValidateKeyBindingAsync(
        string kbJwt,
        JsonWebToken issuerToken,
        string issuerJwt,
        string[] disclosures,
        string expectedAudience,
        string? expectedNonce,
        CancellationToken cancellationToken)
    {
        if (!TokenHandler.CanReadToken(kbJwt))
        {
            return "Invalid key binding token format.";
        }

        JsonWebToken? kbToken;
        try
        {
            kbToken = TokenHandler.ReadJsonWebToken(kbJwt);
        }
        catch (ArgumentException)
        {
            return "Key binding token is malformed.";
        }

        // Extract jwk from header
        if (!kbToken.TryGetHeaderValue<object>("jwk", out var jwkObj) || jwkObj is null)
        {
            return "Key binding token header missing 'jwk' claim.";
        }

        var jwkJson = jwkObj.ToString();
        if (string.IsNullOrWhiteSpace(jwkJson))
        {
            return "Key binding token 'jwk' header is invalid.";
        }

        // Parse holder's public key
        JsonWebKey holderKey;
        try
        {
            holderKey = JsonWebKey.Create(jwkJson);
        }
        catch (ArgumentException)
        {
            return "Key binding token 'jwk' is not a valid JWK.";
        }

        // Validate key binding signature
        var kbValidation = await TokenHandler.ValidateTokenAsync(kbJwt, new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = holderKey,
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(Math.Max(0, _options.AllowedClockSkewSeconds))
        });

        if (!kbValidation.IsValid)
        {
            return "Key binding token signature validation failed.";
        }

        // Validate audience
        if (!kbToken.Audiences.Contains(expectedAudience))
        {
            return $"Key binding token audience mismatch (expected: {expectedAudience}).";
        }

        // Validate nonce if required
        if (_options.RequireKeyBindingNonce)
        {
            if (string.IsNullOrWhiteSpace(expectedNonce)
                || !kbToken.TryGetPayloadValue<string>("nonce", out var nonce)
                || !string.Equals(expectedNonce, nonce, StringComparison.Ordinal))
            {
                return "Key binding nonce is missing or doesn't match.";
            }
        }

        // Validate key binding age (iat claim)
        if (!kbToken.TryGetPayloadValue<long>("iat", out var iat))
        {
            return "Key binding token missing 'iat' claim.";
        }

        var iatTime = DateTimeOffset.FromUnixTimeSeconds(iat);
        var age = _timeProvider.GetUtcNow() - iatTime;
        var maxAge = TimeSpan.FromSeconds(Math.Max(1, _options.KeyBindingMaxAgeSeconds));

        if (age < TimeSpan.Zero || age > maxAge)
        {
            return $"Key binding token is stale (age: {age.TotalSeconds}s, max: {maxAge.TotalSeconds}s).";
        }

        // Validate sd_hash
        if (!kbToken.TryGetPayloadValue<string>("sd_hash", out var sdHash) || string.IsNullOrWhiteSpace(sdHash))
        {
            return "Key binding token missing 'sd_hash' claim.";
        }

        var presentationNoKb = $"{issuerJwt}~{string.Join("~", disclosures)}";
        var presentationNoKbWithTilde = $"{presentationNoKb}~";

        var sdHashNoKb = Base64UrlEncoder.Encode(
            SHA256.HashData(Encoding.ASCII.GetBytes(presentationNoKb)));
        var sdHashNoKbWithTilde = Base64UrlEncoder.Encode(
            SHA256.HashData(Encoding.ASCII.GetBytes(presentationNoKbWithTilde)));

        var sdHashMatches =
            string.Equals(sdHash, sdHashNoKb, StringComparison.Ordinal) ||
            string.Equals(sdHash, sdHashNoKbWithTilde, StringComparison.Ordinal);

        if (!sdHashMatches)
        {
            return "Key binding 'sd_hash' doesn't match presentation.";
        }

        // Validate optional cnf.jkt (holder public key thumbprint)
        if (issuerToken.TryGetPayloadValue<JsonElement>("cnf", out var cnf)
            && cnf.ValueKind == JsonValueKind.Object
            && cnf.TryGetProperty("jkt", out var jkt)
            && !string.IsNullOrWhiteSpace(jkt.GetString()))
        {
            using var jwkDoc = JsonDocument.Parse(jwkJson);
            var holderThumbprint = ComputeJwkThumbprint(jwkDoc.RootElement);
            if (!string.Equals(holderThumbprint, jkt.GetString(), StringComparison.Ordinal))
            {
                return "Key binding holder key thumbprint doesn't match issuer's cnf.jkt.";
            }
        }

        return null; // Validation succeeded
    }

    /// <summary>
    /// Reconstructs claims from the issuer token and disclosed values.
    /// </summary>
    private SdJwtVerificationResult ReconstructClaims(JsonWebToken issuerToken, string[] disclosures)
    {
        var identity = new ClaimsIdentity("SD-JWT");

        // Add non-selective claims from issuer token
        foreach (var claim in issuerToken.Claims)
        {
            // Skip structural claims used for selective disclosure
            if (string.Equals(claim.Type, "_sd", StringComparison.Ordinal)
                || string.Equals(claim.Type, "_sd_alg", StringComparison.Ordinal)
                || string.Equals(claim.Type, "cnf", StringComparison.Ordinal))
            {
                continue;
            }

            identity.AddClaim(claim);
        }

        // Validate and extract disclosure hash algorithm
        var hashAlg = issuerToken.TryGetPayloadValue<string>("_sd_alg", out var value) ? value : "sha-256";

        if (!_options.AllowedDisclosureHashAlgorithms.Contains(hashAlg, StringComparer.OrdinalIgnoreCase))
        {
            return SdJwtVerificationResult.Failure(
                $"Unsupported disclosure hash algorithm: '{hashAlg}'. Allowed: {string.Join(", ", _options.AllowedDisclosureHashAlgorithms)}");
        }

        // Extract the set of allowed disclosure digests from issuer token
        var allowedDigests = ExtractDigests(issuerToken);

        // Process each disclosure
        foreach (var disclosure in disclosures)
        {
            if (string.IsNullOrWhiteSpace(disclosure))
            {
                continue;
            }

            var digest = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(disclosure)));

            if (!allowedDigests.Contains(digest))
            {
                _logger.LogWarning(
                    "Disclosure digest not present in issuer's _sd array (digest: {Digest})", digest);
                continue;
            }

            if (!TryParseDisclosure(disclosure, out var claimName, out var claimValue))
            {
                _logger.LogWarning("Failed to parse disclosure: {Disclosure}", disclosure);
                continue;
            }

            if (!string.IsNullOrWhiteSpace(claimName) && claimValue is not null)
            {
                identity.AddClaim(new Claim(claimName, claimValue));
            }
        }

        return SdJwtVerificationResult.Success(new ClaimsPrincipal(identity));
    }

    /// <summary>
    /// Parses a disclosure array: [salt, claim_name, claim_value].
    /// </summary>
    private static bool TryParseDisclosure(string disclosure, out string? claimName, out string? claimValue)
    {
        claimName = null;
        claimValue = null;

        try
        {
            var decoded = Base64UrlEncoder.DecodeBytes(disclosure);
            using var doc = JsonDocument.Parse(decoded);

            // Disclosure must be an array with 3 elements: [salt, name, value]
            if (doc.RootElement.ValueKind != JsonValueKind.Array || doc.RootElement.GetArrayLength() != 3)
            {
                return false;
            }

            claimName = doc.RootElement[1].GetString();
            if (string.IsNullOrWhiteSpace(claimName))
            {
                return false;
            }

            claimValue = doc.RootElement[2].ToString();
            return claimValue is not null;
        }
#pragma warning disable CA1031  // Continue if disclosure parsing fails
        catch
        {
            return false;
        }
#pragma warning restore CA1031
    }

    /// <summary>
    /// Extracts the set of allowed claim digests from issuer token's _sd array.
    /// </summary>
    private static HashSet<string> ExtractDigests(JsonWebToken token)
    {
        var digests = new HashSet<string>(StringComparer.Ordinal);

        if (!token.TryGetPayloadValue<JsonElement>("_sd", out var sdArray)
            || sdArray.ValueKind != JsonValueKind.Array)
        {
            return digests;
        }

        foreach (var element in sdArray.EnumerateArray())
        {
            var digest = element.GetString();
            if (!string.IsNullOrWhiteSpace(digest))
            {
                digests.Add(digest);
            }
        }

        return digests;
    }

    /// <summary>
    /// Computes the JWK Thumbprint (per RFC 7638) for a given JWK.
    /// Used to verify the key binding holder's public key matches issuer's cnf.jkt.
    /// </summary>
    private static string ComputeJwkThumbprint(JsonElement jwk)
    {
        // RFC 7638 requires lexicographic order: crv, d, dp, dq, e, k, kid, kty, n, oth, p, q, qi, use, x, y
        // For EC keys (when present), include: crv, x, y
        // For RSA keys (when present), include: e, n

        var requiredMembers = new List<string>();

        if (jwk.TryGetProperty("kty", out var ktyElement))
        {
            var kty = ktyElement.GetString();

            if (string.Equals(kty, "RSA", StringComparison.Ordinal))
            {
                // RSA: e, n
                if (jwk.TryGetProperty("e", out _)) requiredMembers.Add("e");
                if (jwk.TryGetProperty("n", out _)) requiredMembers.Add("n");
            }
            else if (string.Equals(kty, "EC", StringComparison.Ordinal))
            {
                // EC: crv, x, y
                if (jwk.TryGetProperty("crv", out _)) requiredMembers.Add("crv");
                if (jwk.TryGetProperty("x", out _)) requiredMembers.Add("x");
                if (jwk.TryGetProperty("y", out _)) requiredMembers.Add("y");
            }
            // Add kty as well
            requiredMembers.Insert(0, "kty");
        }

        // Build lexicographically ordered JSON
        var orderedJson = "{";
        var first = true;

        foreach (var member in requiredMembers.OrderBy(m => m))
        {
            if (jwk.TryGetProperty(member, out var value))
            {
                if (!first) orderedJson += ",";
                orderedJson += $"\"{member}\":{value.GetRawText()}";
                first = false;
            }
        }

        orderedJson += "}";

        // Compute SHA-256 and encode
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(orderedJson));
        return Base64UrlEncoder.Encode(hashBytes);
    }
}
