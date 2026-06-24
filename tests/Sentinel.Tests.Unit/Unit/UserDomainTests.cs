using System;
using System.Collections.Generic;
using System.Linq;
using FluentAssertions;
using Sentinel.Domain.Users;
using Xunit;

namespace Sentinel.Tests.Unit.Unit;

public sealed class UserDomainTests
{
    private static readonly ConsentInfo ValidConsent = ConsentInfo.Create(
        accepted: true,
        policyVersion: "1.0",
        rawIp: "192.168.1.1",
        timestamp: DateTimeOffset.UtcNow);

    [Fact(DisplayName = "✅ Domain: Constructor successfully trims and normalizes email")]
    public void Constructor_WithValidParams_TrimsAndNormalizesEmail()
    {
        const string rawEmail = "  User.SECURE@sentinel.GE  ";
        const string username = "secure_user_1";

        var sut = new UserRegistration(rawEmail, username, ValidConsent);

        sut.Id.Should().NotBeEmpty();
        sut.Email.Should().Be("user.secure@sentinel.ge");
        sut.Username.Should().Be("secure_user_1");
        sut.Consent.Should().Be(ValidConsent);
    }

    [Theory(DisplayName = "🔴 Domain: Empty or whitespace email violates invariant and throws")]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_WithEmptyEmail_ThrowsArgumentException(string? invalidEmail)
    {
        var act = () => new UserRegistration(invalidEmail!, "user", ValidConsent);

        act.Should().Throw<ArgumentException>()
            .WithParameterName("email");
    }

    [Fact(DisplayName = "🔴 Domain: Null Consent violates invariant and throws")]
    public void Constructor_WithNullConsent_ThrowsArgumentNullException()
    {
        var act = () => new UserRegistration("email@test.com", "user", null!);

        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("consent");
    }

    [Fact(DisplayName = "✓ Domain: Parameterless constructor works for Native AOT deserialization")]
    public void ParameterlessConstructor_CreatesEmptyInstance()
    {
        var sut = new UserRegistration();

        sut.Id.Should().BeEmpty();
        sut.Email.Should().BeEmpty();
        sut.Username.Should().BeEmpty();
        sut.Consent.Should().BeNull();
    }

    [Fact(DisplayName = "✅ Domain: ConsentInfo.Create successfully hashes IP for GDPR compliance")]
    public void Create_WithValidParams_HashesIpAndSaves()
    {
        var now = DateTimeOffset.UtcNow;
        const string rawIp = "2001:db8:85d3:8d3:1319:8a2e:370:7348";

        var sut = ConsentInfo.Create(accepted: true, policyVersion: "2.1", rawIp: rawIp, timestamp: now);

        sut.TermsAccepted.Should().BeTrue();
        sut.PrivacyPolicyVersion.Should().Be("2.1");
        sut.AcceptedAtUtc.Should().Be(now);

        sut.SourceIpHash.Should().NotContain(rawIp);
        sut.SourceIpHash.Should().NotBeNullOrWhiteSpace();
        sut.SourceIpHash.Should().MatchRegex(@"^[A-Za-z0-9+/=]+$");
    }

    [Fact(DisplayName = "🔴 Domain: Terms not accepted violates consent invariant and throws")]
    public void Create_WithTermsNotAccepted_ThrowsInvalidOperationException()
    {
        var act = () => ConsentInfo.Create(accepted: false, "1.0", "127.0.0.1", DateTimeOffset.UtcNow);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("Consent invariant violated: Terms must be explicitly accepted.");
    }

    [Theory(DisplayName = "🔴 Domain: Empty privacy policy version violates consent invariant and throws")]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Create_WithEmptyPolicyVersion_ThrowsArgumentException(string? invalidVersion)
    {
        var act = () => ConsentInfo.Create(accepted: true, invalidVersion!, "127.0.0.1", DateTimeOffset.UtcNow);

        act.Should().Throw<ArgumentException>()
            .WithParameterName("policyVersion");
    }

    [Theory(DisplayName = "✓ Domain: Empty or invalid IP returns GDPR-safe anonymous placeholder")]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Create_WithEmptyIp_ReturnsAnonymousPlaceholder(string? emptyIp)
    {
        var sut = ConsentInfo.Create(accepted: true, "1.0", emptyIp!, DateTimeOffset.UtcNow);

        sut.SourceIpHash.Should().Be("[anonymous]", "GDPR mandates providing anonymous placeholders for missing PII.");
    }

    [Fact(DisplayName = "✓ Domain: IP hashing is deterministic and produces consistent HMAC hashes")]
    public void Create_WithSameIp_ProducesIdenticalHashes()
    {
        const string ip = "192.168.1.100";
        var now = DateTimeOffset.UtcNow;

        var sut1 = ConsentInfo.Create(true, "1.0", ip, now);
        var sut2 = ConsentInfo.Create(true, "1.0", ip, now);

        sut1.SourceIpHash.Should().Be(sut2.SourceIpHash, "Same input must produce identical HMAC output for audit indexing.");
    }
}
