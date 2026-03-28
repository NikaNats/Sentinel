using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Sentinel.Tests.Security.Helpers;

/// <summary>
///     Protocol Mutation Engine for negative testing.
///     Systematically corrupts valid cryptographic structures (JWT, DPoP, SD-JWT)
///     to test resilience against malformed and adversarial input.
///     Why this matters in .NET 10 Native AOT:
///     - With runtime safety net removed, a single unhandled NullReferenceException
///     in a SIMD-optimized JSON parser can destabilize the entire pipeline.
///     - This engine generates deterministic mutations (not random fuzzing) to catch
///     edge cases while maintaining reproducibility in CI/CD.
/// </summary>
public static class TokenPoisoner
{
    // High-entropy "Poison" bytes for UTF-8 and Base64Url attacks
    private static readonly string[] PoisonStrings =
    [
        "..\\..\\..\\", // Path Traversal attempt
        "\u0000", // Null Byte
        "\uFFFD", // Unicode Replacement Character
        "{\"\" : { \"\" : { \"\" : \"\"}}}", // Deeply nested JSON
        "A" + new string('0', 10000), // Large buffer (stack/heap attack)
        "\xC0\xAF", // Overlong UTF-8 encoding of "/"
        "%%%%%%%s%s%s", // Format string attempt
        "NaN", // Numerical edge case
        "true", // Type confusion (boolean vs string)
        "[null, null]" // Array confusion
    ];

    /// <summary>
    ///     Generates a series of mutations (corruptions) of a valid JWT token
    ///     to stress-test validators against structural and payload attacks.
    /// </summary>
    /// <param name="validToken">A well-formed JWT (3 base64url-encoded parts separated by dots)</param>
    /// <returns>Enumerable of poisoned token strings that should all fail validation</returns>
    public static IEnumerable<string> GenerateMutations(string validToken)
    {
        var parts = validToken.Split('.');

        if (parts.Length != 3)
        {
            throw new ArgumentException("Token must be a valid 3-part JWT (header.payload.signature)",
                nameof(validToken));
        }

        // 1. Structure Attack: Wrong number of segments
        yield return validToken + ".extra_segment";
        yield return parts[0] + "." + parts[1]; // Missing signature

        // 2. Base64Url Attack: Illegal characters
        yield return validToken.Replace('a', '!');
        yield return validToken + "==="; // Force illegal padding

        // 3. Segment Mutation: Inject poison into each part
        foreach (var poison in PoisonStrings)
        {
            var poisonBase64 = Base64UrlEncoder.Encode(poison);

            // Poison Header
            yield return $"{poisonBase64}.{parts[1]}.{parts[2]}";

            // Poison Payload
            yield return $"{parts[0]}.{poisonBase64}.{parts[2]}";

            // Poison Signature
            yield return $"{parts[0]}.{parts[1]}.{poisonBase64}";
        }

        // 4. Bit-Flipping Attack: Randomly corrupt 1 byte in random segments
        using (var rng = RandomNumberGenerator.Create())
        {
            for (var i = 0; i < 5; i++)
            {
                var bytes = Encoding.UTF8.GetBytes(validToken);
                var indexBytes = new byte[4];
                rng.GetBytes(indexBytes);
                var index = Math.Abs(BitConverter.ToInt32(indexBytes, 0)) % bytes.Length;
                bytes[index] = (byte)(bytes[index] ^ 0xFF); // XOR flip all bits
                yield return Encoding.UTF8.GetString(bytes);
            }
        }

        // 5. Truncation Attack: Cut off at various points
        for (var i = 1; i < validToken.Length; i++)
        {
            yield return validToken.Substring(0, validToken.Length - i);
        }

        // 6. Empty segments
        yield return $".{parts[1]}.{parts[2]}";
        yield return $"{parts[0]}..{parts[2]}";
        yield return $"{parts[0]}.{parts[1]}.";

        // 7. Duplicate parts (possible replay/confusion attacks)
        yield return $"{parts[0]}.{parts[0]}.{parts[2]}";
        yield return $"{parts[0]}.{parts[1]}.{parts[0]}";
    }

    /// <summary>
    ///     Generates mutations of a valid SD-JWT presentation.
    ///     SD-JWT uses '~' as a disclosure separator, unlike JWT's '.'.
    ///     This creates new attack surface for confusion attacks.
    /// </summary>
    /// <param name="validPresentation">Valid SD-JWT presentation (jwt~disclosure1~kb_jwt)</param>
    /// <returns>Enumerable of poisoned SD-JWT presentations</returns>
    public static IEnumerable<string> GenerateSdJwtMutations(string validPresentation)
    {
        // 1. Separator confusion: Replace ~ with . to confuse parsers
        yield return validPresentation.Replace('~', '.');

        // 2. Empty segments
        yield return "~~~";
        yield return "~" + validPresentation;
        yield return validPresentation + "~";

        // 3. Poison disclosure segments
        var poisonDisclosure = Base64UrlEncoder.Encode("\0\0\0\0\0");
        yield return validPresentation + "~" + poisonDisclosure;

        // 4. Missing entire components
        var parts = validPresentation.Split('~');
        if (parts.Length > 1)
        {
            yield return parts[0]; // Just the JWT, no disclosures
            yield return string.Join("~", parts.Take(parts.Length - 1)); // Missing KB-JWT
        }

        // 5. Duplicate components
        if (parts.Length >= 3)
        {
            yield return $"{parts[0]}~{parts[1]}~{parts[1]}~{parts[2]}";
        }

        // 6. Extremely long disclosure chains
        var longDisclosure = string.Join(
            "~",
            Enumerable.Range(0, 1000).Select(_ => Base64UrlEncoder.Encode("data")));
        yield return $"{parts[0]}~{longDisclosure}";
    }

    /// <summary>
    ///     Generates completely random token-like strings to stress
    ///     the Base64Url decoder's error handling paths.
    /// </summary>
    /// <param name="count">Number of random tokens to generate</param>
    /// <returns>Enumerable of random byte sequences as base64url strings</returns>
    public static IEnumerable<string> GenerateRandomTokens(int count = 10)
    {
        using (var rng = RandomNumberGenerator.Create())
        {
            for (var i = 0; i < count; i++)
            {
                var sizeBytes = new byte[4];
                rng.GetBytes(sizeBytes);
                var size = Math.Abs(BitConverter.ToInt32(sizeBytes, 0) % 256) + 1;

                var randomBytes = new byte[size];
                rng.GetBytes(randomBytes);
                yield return Convert.ToBase64String(randomBytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
            }
        }
    }
}
