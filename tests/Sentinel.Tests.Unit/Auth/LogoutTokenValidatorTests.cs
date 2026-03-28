using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Sentinel.Infrastructure.Auth;

namespace Sentinel.Tests.Unit.Auth;

/// <summary>
///     RFC 6587 OIDC Backchannel Logout Token Validation Tests
///     OIDC Backchannel Logout (RFC 9413) mandates strict requirements:
///     - Logout tokens MUST NOT contain a 'nonce' claim (distinguishes from ID tokens)
///     - Logout tokens MUST contain an 'events' claim with backchannel-logout event
///     - Missing these triggers a security rejection (prevents token replay attacks)
///     These tests verify compliance and prevent CVE-class vulnerabilities where
///     a standard ID token could be repurposed as a logout token.
/// </summary>
public sealed class LogoutTokenValidatorTests
{
    private readonly Mock<IOptionsMonitor<JwtBearerOptions>> _optionsMonitorMock;
    private readonly ECDsaSecurityKey _securityKey;
    private readonly ECDsa _signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly LogoutTokenValidator _sut;

    public LogoutTokenValidatorTests()
    {
        _securityKey = new ECDsaSecurityKey(_signingKey) { KeyId = "test-key" };
        var options = new JwtBearerOptions
        {
            TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = _securityKey,
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = false
            }
        };

        _optionsMonitorMock = new Mock<IOptionsMonitor<JwtBearerOptions>>();
        _optionsMonitorMock
            .Setup(m => m.Get(JwtBearerDefaults.AuthenticationScheme))
            .Returns(options);

        _sut = new LogoutTokenValidator(_optionsMonitorMock.Object, NullLogger<LogoutTokenValidator>.Instance);
    }

    [Fact]
    public async Task ValidateAndExtractSessionIdAsync_WhenForbiddenNoncePresent_ReturnsNull()
    {
        // RFC 9413 Section 2: Logout tokens MUST NOT contain a nonce claim
        // This test ensures attacker cannot replay an ID token as a logout token
        var token = CreateToken(new Dictionary<string, object>
        {
            ["sid"] = "session-123",
            ["nonce"] = "forbidden-nonce", // MUST be rejected
            ["events"] = new Dictionary<string, object>
            {
                ["http://schemas.openid.net/event/backchannel-logout"] = true
            }
        });

        var result = await _sut.ValidateAndExtractSessionIdAsync(token, CancellationToken.None);

        result.Should().BeNull("Logout tokens MUST NOT contain nonce per RFC 9413");
    }

    [Fact]
    public async Task ValidateAndExtractSessionIdAsync_WhenEventsClaimMissing_ReturnsNull()
    {
        // RFC 9413 Section 2: MUST contain the backchannel-logout event
        // Missing events claim means this is not a valid logout token
        var token = CreateToken(new Dictionary<string, object>
        {
            ["sid"] = "session-123"
            // Missing 'events' claim entirely
        });

        var result = await _sut.ValidateAndExtractSessionIdAsync(token, CancellationToken.None);

        result.Should().BeNull("Logout tokens MUST contain events claim per RFC 9413");
    }

    [Fact]
    public async Task ValidateAndExtractSessionIdAsync_WhenBackchannelLogoutEventMissing_ReturnsNull()
    {
        // RFC 9413 Section 2: Must have SPECIFIC backchannel-logout event
        // Having an 'events' claim but wrong event type is invalid
        var token = CreateToken(new Dictionary<string, object>
        {
            ["sid"] = "session-123",
            ["events"] = new Dictionary<string, object>
            {
                ["http://schemas.openid.net/event/wrong-event-type"] = true
            }
        });

        var result = await _sut.ValidateAndExtractSessionIdAsync(token, CancellationToken.None);

        result.Should().BeNull("Logout tokens MUST contain backchannel-logout event");
    }

    [Fact]
    public async Task ValidateAndExtractSessionIdAsync_WhenValidCompliant_ReturnsSid()
    {
        // RFC 9413 compliant logout token: has sid, has events claim, no nonce
        var expectedSid = "session-secure-uuid-1234";
        var token = CreateToken(new Dictionary<string, object>
        {
            ["sid"] = expectedSid,
            ["events"] = new Dictionary<string, object>
            {
                ["http://schemas.openid.net/event/backchannel-logout"] = true
            }
        });

        var result = await _sut.ValidateAndExtractSessionIdAsync(token, CancellationToken.None);

        result.Should().Be(expectedSid);
    }

    [Fact]
    public async Task ValidateAndExtractSessionIdAsync_WhenSidMissing_ReturnsNull()
    {
        // RFC 9413: sid (session identifier) is essential to identify which session to logout
        var token = CreateToken(new Dictionary<string, object>
        {
            // Missing 'sid'
            ["events"] = new Dictionary<string, object>
            {
                ["http://schemas.openid.net/event/backchannel-logout"] = true
            }
        });

        var result = await _sut.ValidateAndExtractSessionIdAsync(token, CancellationToken.None);

        result.Should().BeNull("Logout tokens MUST contain sid claim");
    }

    private string CreateToken(Dictionary<string, object> customClaims)
    {
        var claims = new Dictionary<string, object>
        {
            ["iss"] = "https://issuer",
            ["aud"] = "api",
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["exp"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()
        };

        foreach (var c in customClaims)
        {
            claims[c.Key] = c.Value;
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            SigningCredentials = new SigningCredentials(_securityKey, SecurityAlgorithms.EcdsaSha256)
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }
}
