using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Infrastructure.Auth;

namespace Sentinel.Tests.Unit;

public sealed class DpopThumbprintHelperTests
{
    [Fact]
    public void ComputeJwkThumbprint_WhenEcJwkProvided_ReturnsThumbprint()
    {
        using var doc = JsonDocument.Parse("""{ "kty": "EC", "crv": "P-256", "x": "abc", "y": "def" }""");

        var thumbprint = DpopThumbprintHelper.ComputeJwkThumbprint(doc.RootElement);

        Assert.False(string.IsNullOrWhiteSpace(thumbprint));
    }

    [Fact]
    public void ComputeJwkThumbprint_WhenRsaJwkProvided_ReturnsThumbprint()
    {
        using var doc = JsonDocument.Parse("""{ "kty": "RSA", "e": "AQAB", "n": "abc123" }""");

        var thumbprint = DpopThumbprintHelper.ComputeJwkThumbprint(doc.RootElement);

        Assert.False(string.IsNullOrWhiteSpace(thumbprint));
    }

    [Fact]
    public void ComputeJwkThumbprint_WhenMlDsaJwkProvided_ReturnsExpectedThumbprint()
    {
        using var doc = JsonDocument.Parse("""{ "kty": "ML-DSA", "x": "pq-public-key" }""");
        var expectedCanonical = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["kty"] = "ML-DSA",
            ["x"] = "pq-public-key"
        });
        var expected = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(expectedCanonical)));

        var thumbprint = DpopThumbprintHelper.ComputeJwkThumbprint(doc.RootElement);

        Assert.Equal(expected, thumbprint);
    }

    [Fact]
    public void ComputeJwkThumbprint_WhenJwkTypeUnsupported_ReturnsEmpty()
    {
        using var doc = JsonDocument.Parse("""{ "kty": "oct", "k": "secret" }""");

        var thumbprint = DpopThumbprintHelper.ComputeJwkThumbprint(doc.RootElement);

        Assert.Equal(string.Empty, thumbprint);
    }
}
