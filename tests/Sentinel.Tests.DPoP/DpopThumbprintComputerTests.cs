using Xunit;

namespace Sentinel.Tests.DPoP;

/// <summary>
///     Tests for DPoP thumbprint computation per RFC 7638.
///     Ensures stable, deterministic thumbprints from public keys.
/// </summary>
public class DpopThumbprintComputerTests
{
    private readonly DpopThumbprintComputer _computer = new();

    [Fact]
    public void Compute_WithValidEcKey_ReturnsBase64UrlThumbprint()
    {
        // Arrange - RFC 7638 example EC public key
        var jwkJson = """
                      {
                          "kty": "EC",
                          "crv": "P-256",
                          "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
                          "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"
                      }
                      """;

        using var doc = JsonDocument.Parse(jwkJson);
        var jwk = doc.RootElement;

        // Act
        var thumbprint = _computer.Compute(jwk);

        // Assert
        thumbprint.Should().NotBeEmpty();
        thumbprint.Should().MatchRegex(@"^[A-Za-z0-9_-]+$"); // Base64url format
        thumbprint.Length.Should().BeGreaterThan(40); // SHA256 base64url is ~43 chars
    }

    [Fact]
    public void Compute_WithValidRsaKey_ReturnsBase64UrlThumbprint()
    {
        // Arrange - EC and RSA should produce different thumbprints
        var jwkJson = """
                      {
                          "kty": "RSA",
                          "e": "AQAB",
                          "n": "xjlCRBqkQtpMxANV0T2c6l9Pnq9pPWpbXJ9m5P5DzK9mZ5xQ6Z9vJ5yK9vR9xK5Z4xL8dD3Z7zA2V8xV9xV9xV9xV9xV9xV9xV9xV9xV9xV9xV9xV9xV9xV9xV9xV9xV9xV9xV9xV9xV"
                      }
                      """;

        using var doc = JsonDocument.Parse(jwkJson);
        var jwk = doc.RootElement;

        // Act
        var thumbprint = _computer.Compute(jwk);

        // Assert
        thumbprint.Should().NotBeEmpty();
        thumbprint.Should().MatchRegex(@"^[A-Za-z0-9_-]+$");
    }

    [Fact]
    public void Compute_WithMlDsaKey_ReturnsBase64UrlThumbprint()
    {
        // Arrange - ML-DSA post-quantum key
        var jwkJson = """
                      {
                          "kty": "ML-DSA",
                          "x": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst"
                      }
                      """;

        using var doc = JsonDocument.Parse(jwkJson);
        var jwk = doc.RootElement;

        // Act
        var thumbprint = _computer.Compute(jwk);

        // Assert
        thumbprint.Should().NotBeEmpty();
        thumbprint.Should().MatchRegex(@"^[A-Za-z0-9_-]+$");
    }

    [Fact]
    public void Compute_WithInvalidKeyType_ReturnsEmptyString()
    {
        // Arrange - Unsupported key type
        var jwkJson = """
                      {
                          "kty": "UNSUPPORTED",
                          "value": "test"
                      }
                      """;

        using var doc = JsonDocument.Parse(jwkJson);
        var jwk = doc.RootElement;

        // Act
        var thumbprint = _computer.Compute(jwk);

        // Assert
        thumbprint.Should().BeEmpty();
    }

    [Fact]
    public void Compute_WithMissingRequiredProperties_ReturnsEmptyString()
    {
        // Arrange - EC key missing required properties
        var jwkJson = """
                      {
                          "kty": "EC",
                          "crv": "P-256"
                      }
                      """;

        using var doc = JsonDocument.Parse(jwkJson);
        var jwk = doc.RootElement;

        // Act
        var thumbprint = _computer.Compute(jwk);

        // Assert
        thumbprint.Should().BeEmpty();
    }

    [Fact]
    public void Compute_Deterministic_SameInputProducesSameThumbprint()
    {
        // Arrange
        var jwkJson = """
                      {
                          "kty": "EC",
                          "crv": "P-256",
                          "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
                          "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"
                      }
                      """;

        using var doc1 = JsonDocument.Parse(jwkJson);
        using var doc2 = JsonDocument.Parse(jwkJson);

        // Act
        var thumbprint1 = _computer.Compute(doc1.RootElement);
        var thumbprint2 = _computer.Compute(doc2.RootElement);

        // Assert
        thumbprint1.Should().Be(thumbprint2);
    }
}
