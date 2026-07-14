using System.Buffers;
using Microsoft.Extensions.Logging.Abstractions;

namespace Sentinel.SdJwt;

/// <summary>
///     Processes and verifies Selective Disclosure JWT (SD-JWT) presentations (RFC 9901).
///     Handles format validation, disclosure digest verification, and key binding validation.
/// </summary>
public sealed class SdJwtPresenter : ISdJwtPresenter
{
    private static readonly JsonWebTokenHandler TokenHandler = new();
    private readonly ILogger<SdJwtPresenter> _logger;
    private readonly SdJwtVerificationOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly ISdJwtTokenValidator _tokenValidator;

    /// <summary>
    ///     Initializes a new instance of the SdJwtPresenter.
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
        _logger = logger ?? NullLogger<SdJwtPresenter>.Instance;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    ///     Verifies an SD-JWT presentation with optional key binding.
    /// </summary>
    /// <remarks>
    ///     SD-JWT presentation format: issuer_jwt~disclosure1~disclosure2~...~key_binding_jwt
    ///     Verification process:
    ///     1. Parses presentation format (issuer JWT, disclosures, key binding JWT)
    ///     2. Validates issuer token signature and claims
    ///     3. Validates key binding JWT signature, age, and sd_hash
    ///     4. Reconstructs claims from disclosures based on _sd digests
    ///     5. Returns ClaimsPrincipal with disclosed claims
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
#pragma warning disable CA1031 // Recover from all exceptions
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during SD-JWT verification");
            return SdJwtVerificationResult.Failure("SD-JWT verification failed due to an internal error.");
        }
#pragma warning restore CA1031
    }

    /// <summary>
    ///     Validates the key binding JWT and verifies sd_hash.
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

        // Validate key binding signature and audience via cryptographic handler
        // (not manual string comparison, which can be bypassed)
        var kbValidation = await TokenHandler.ValidateTokenAsync(kbJwt, new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = holderKey,
            ValidateIssuer = false,
            ValidateAudience = true,
            ValidAudiences = [expectedAudience],
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(Math.Max(0, _options.AllowedClockSkewSeconds))
        });

        if (!kbValidation.IsValid)
        {
            return "Key binding token signature or audience validation failed.";
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

        if (!issuerToken.TryGetPayloadValue<JsonElement>("cnf", out var cnf)
            || cnf.ValueKind != JsonValueKind.Object
            || !cnf.TryGetProperty("jkt", out var jkt)
            || string.IsNullOrWhiteSpace(jkt.GetString()))
        {
            return "Issuer SD-JWT is missing required cnf.jkt holder binding.";
        }

        var jktValue = jkt.GetString()!;
        using var jwkDoc = JsonDocument.Parse(jwkJson);
        var holderThumbprint = ComputeJwkThumbprint(jwkDoc.RootElement);


        var holderThumbprintBytes = Encoding.ASCII.GetBytes(holderThumbprint);
        var jktBytes = Encoding.ASCII.GetBytes(jktValue);

        if (!CryptographicOperations.FixedTimeEquals(holderThumbprintBytes, jktBytes))
        {
            return "Key binding holder key thumbprint doesn't match issuer's cnf.jkt.";
        }

        return null;
    }

    /// <summary>
    ///     Reconstructs claims from the issuer token and disclosed values.
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
                // Hash disclosure for log correlation without exposing PII (GDPR/CPRA compliance)
                var disclosureHash = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(disclosure)));
                _logger.LogWarning("Failed to parse disclosure (hash: {DisclosureHash})", disclosureHash);
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
    ///     Parses a disclosure array: [salt, claim_name, claim_value].
    ///     Preserves numeric types (int/long/double), booleans, and complex values (JSON objects/arrays).
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

            // Extract claim value with type preservation
            var valueElement = doc.RootElement[2];
            claimValue = ConvertJsonElementToClaimValue(valueElement);

            return claimValue is not null;
        }
#pragma warning disable CA1031 // Continue if disclosure parsing fails
        catch
        {
            return false;
        }
#pragma warning restore CA1031
    }

    /// <summary>
    ///     Converts a JsonElement to a string claim value, preserving type information.
    ///     - Numbers remain as numeric strings (int64, double)
    ///     - Booleans become "true"/"false" strings
    ///     - Objects/Arrays become JSON strings (for complex valued claims)
    ///     - Strings remain unchanged
    /// </summary>
    private static string? ConvertJsonElementToClaimValue(JsonElement element) =>
        element.ValueKind switch
        {
            JsonValueKind.String => element.GetString(),
            JsonValueKind.Number => element.GetRawText(), // Preserves exact numeric representation
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Null => null,
            // For complex types (Object, Array), serialize as JSON string
            JsonValueKind.Object or JsonValueKind.Array => element.GetRawText(),
            _ => null
        };

    /// <summary>
    ///     Extracts the set of allowed claim digests from issuer token's _sd arrays.
    ///     RFC 9901 allows nested selective disclosure: _sd can appear at any depth in object hierarchy.
    ///     Performs recursive deep traversal to find all _sd digests (root + nested objects/arrays).
    /// </summary>
    private static HashSet<string> ExtractDigests(JsonWebToken token)
    {
        var digests = new HashSet<string>(StringComparer.Ordinal);

        if (!token.TryGetPayloadValue<JsonElement>("_sd", out var payload))
        {
            return digests;
        }

        if (payload.ValueKind == JsonValueKind.Array)
        {
            foreach (var sdElement in payload.EnumerateArray())
            {
                var digest = sdElement.GetString();
                if (!string.IsNullOrWhiteSpace(digest))
                {
                    digests.Add(digest);
                }
            }

            return digests;
        }

        // Start recursive extraction from token payload (typically an object)
        ExtractDigestsRecursive(payload, digests);
        return digests;
    }

    /// <summary>
    ///     Recursively extracts all _sd digest values from a JSON structure at any nesting depth.
    ///     Traverses objects and arrays to find all _sd arrays (RFC 9901 nested disclosure support).
    /// </summary>
    private static void ExtractDigestsRecursive(JsonElement element, HashSet<string> digests)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                // Check for _sd array at this level
                if (element.TryGetProperty("_sd", out var sdArray) && sdArray.ValueKind == JsonValueKind.Array)
                {
                    foreach (var sdElement in sdArray.EnumerateArray())
                    {
                        var digest = sdElement.GetString();
                        if (!string.IsNullOrWhiteSpace(digest))
                        {
                            digests.Add(digest);
                        }
                    }
                }

                // Recursively process all properties
                foreach (var property in element.EnumerateObject())
                {
                    // Skip structural SD-JWT fields
                    if (!string.Equals(property.Name, "_sd", StringComparison.Ordinal)
                        && !string.Equals(property.Name, "_sd_alg", StringComparison.Ordinal)
                        && !string.Equals(property.Name, "cnf", StringComparison.Ordinal))
                    {
                        ExtractDigestsRecursive(property.Value, digests);
                    }
                }

                break;

            case JsonValueKind.Array:
                // Recursively process array elements
                foreach (var arrayElement in element.EnumerateArray())
                {
                    ExtractDigestsRecursive(arrayElement, digests);
                }

                break;

            // Primitive values (String, Number, True, False, Null) have no nested disclosures
        }
    }

    /// <summary>
    ///     Computes the JWK Thumbprint (per RFC 7638) for a given JWK.
    ///     Used to verify the key binding holder's public key matches issuer's cnf.jkt.
    ///     RFC 7638 requires strict canonical JSON: lexicographic ordering, no whitespace,
    ///     exact UTF-8 encoding with preserved numeric precision via Utf8JsonWriter.
    /// </summary>
    private static string ComputeJwkThumbprint(JsonElement jwk)
    {
        // RFC 7638 Section 3: Required members per key type
        var requiredMembers = new SortedDictionary<string, JsonElement>(StringComparer.Ordinal);

        if (!jwk.TryGetProperty("kty", out var ktyElement))
        {
            return string.Empty; // Invalid JWK
        }

        var kty = ktyElement.GetString();

        // Always include kty (required for all key types)
        requiredMembers["kty"] = ktyElement;

        // RFC 7638 Table 1: Extract type-specific required members
        switch (kty)
        {
            case "RSA":
                if (jwk.TryGetProperty("e", out var e))
                {
                    requiredMembers["e"] = e;
                }

                if (jwk.TryGetProperty("n", out var n))
                {
                    requiredMembers["n"] = n;
                }

                break;

            case "EC":
                if (jwk.TryGetProperty("crv", out var crv))
                {
                    requiredMembers["crv"] = crv;
                }

                if (jwk.TryGetProperty("x", out var x))
                {
                    requiredMembers["x"] = x;
                }

                if (jwk.TryGetProperty("y", out var y))
                {
                    requiredMembers["y"] = y;
                }

                break;

            case "oct":
                if (jwk.TryGetProperty("k", out var k))
                {
                    requiredMembers["k"] = k;
                }

                break;

            // For other key types, kty is sufficient
        }

        // Construct canonical JSON via Utf8JsonWriter (zero-allocation, strict compliance)
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = false });

        writer.WriteStartObject();

        // Write members in lexicographic order (SortedDictionary guarantees this)
        foreach (var kvp in requiredMembers)
        {
            writer.WritePropertyName(kvp.Key);
            kvp.Value.WriteTo(writer);
        }

        writer.WriteEndObject();
        writer.Flush();

        // Compute SHA-256 thumbprint of canonical JSON
        var hashBytes = SHA256.HashData(buffer.WrittenMemory.Span);
        return Base64UrlEncoder.Encode(hashBytes);
    }
}
