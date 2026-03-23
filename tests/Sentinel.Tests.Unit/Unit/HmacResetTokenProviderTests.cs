using Microsoft.Extensions.Options;
using Sentinel.Security.Tokens;

namespace Sentinel.Tests.Unit;

public sealed class HmacResetTokenProviderTests
{
    [Fact]
    public void GenerateAndValidateToken_WhenUntampered_ReturnsEmail()
    {
        var provider = BuildProvider();

        var token = provider.GenerateToken("user@example.com");
        var (isValid, email) = provider.ValidateToken(token);

        Assert.True(isValid);
        Assert.Equal("user@example.com", email);
    }

    [Fact]
    public void ValidateToken_WhenTampered_ReturnsInvalid()
    {
        var provider = BuildProvider();
        var token = provider.GenerateToken("user@example.com");
        var tampered = token + "a";

        var (isValid, email) = provider.ValidateToken(tampered);

        Assert.False(isValid);
        Assert.Null(email);
    }

    private static HmacResetTokenProvider BuildProvider()
    {
        var options = Options.Create(new ResetTokenOptions
        {
            TokenSigningKey =
                Convert.ToBase64String(Guid.NewGuid().ToByteArray().Concat(Guid.NewGuid().ToByteArray()).ToArray()),
            LifetimeMinutes = 15
        });

        return new HmacResetTokenProvider(options);
    }
}
