using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Sentinel.SdJwt;

namespace Sentinel.Tests.Unit.Unit;

public sealed class SdJwtPresenterTests : IDisposable
{
    private readonly ECDsa _ecdsa;
    private readonly ECDsaSecurityKey _securityKey;
    private readonly SdJwtPresenter _sut;
    private readonly Mock<ISdJwtTokenValidator> _validatorMock = new();

    public SdJwtPresenterTests()
    {
        _sut = new SdJwtPresenter(_validatorMock.Object, new SdJwtVerificationOptions
        {
            RequireKeyBindingNonce = false,
            AllowedClockSkewSeconds = 60,
            KeyBindingMaxAgeSeconds = 300
        }, NullLogger<SdJwtPresenter>.Instance);

        _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _securityKey = new ECDsaSecurityKey(_ecdsa) { KeyId = "test-authority-key" };
    }

    public void Dispose() => _ecdsa.Dispose();

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public async Task VerifyPresentationAsync_WhenPresentationIsEmpty_ReturnsFailure(string presentation)
    {
        // Act
        var result = await _sut.VerifyPresentationAsync(presentation ?? "", "audience");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrWhiteSpace();
    }

    [Theory]
    [InlineData("just-one-part")]
    [InlineData("part1~toomanyparts")]
    public async Task VerifyPresentationAsync_WhenFormatIsInvalid_ReturnsFailure(string presentation)
    {
        // Act
        var result = await _sut.VerifyPresentationAsync(presentation, "audience");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task VerifyPresentationAsync_WhenIssuerValidationFails_ReturnsFailure()
    {
        // Arrange
        _validatorMock
            .Setup(x => x.ValidateIssuerTokenAsync(It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(SdJwtIssuerTokenValidationResult.Failure("Issuer invalid"));

        // Act
        var result = await _sut.VerifyPresentationAsync("issuer~kb", "audience");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().Contain("invalid");
    }

    [Fact]
    public async Task VerifyPresentationAsync_WhenTokenValidationThrows_CatchesAndFailsClosed()
    {
        // Arrange
        _validatorMock
            .Setup(x => x.ValidateIssuerTokenAsync(It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Network down"));

        // Act
        var result = await _sut.VerifyPresentationAsync("issuer~kb", "audience");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task VerifyPresentationAsync_WhenOperationCancelled_ReturnsFailure()
    {
        // Arrange
        _validatorMock
            .Setup(x => x.ValidateIssuerTokenAsync(It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new OperationCanceledException());

        // Act
        var result = await _sut.VerifyPresentationAsync("issuer~kb", "audience");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task VerifyPresentationAsync_WhenMultipleDisclosures_ParsesCorrectly()
    {
        // Arrange - presentation with multiple disclosures: issuer~disclosure1~disclosure2~kb
        var presentation = "issuer~disclosure1~disclosure2~kb";

        _validatorMock
            .Setup(x => x.ValidateIssuerTokenAsync(It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(SdJwtIssuerTokenValidationResult.Failure("Validation fails for testing boundary"));

        // Act
        var result = await _sut.VerifyPresentationAsync(presentation, "audience");

        // Assert
        // Should attempt validation and fail gracefully
        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyPresentationAsync_WithMissingIssuerJwt_ReturnsFailure()
    {
        // Arrange - presentation starts with ~ (empty issuer)
        var presentation = "~disclosure~kb";

        // Act
        var result = await _sut.VerifyPresentationAsync(presentation, "audience");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task VerifyPresentationAsync_WithMissingKeyBinding_ReturnsFailure()
    {
        // Arrange - presentation ends with ~ (empty key binding)
        var presentation = "issuer~disclosure~";

        // Act
        var result = await _sut.VerifyPresentationAsync(presentation, "audience");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrWhiteSpace();
    }

    // =========================================================================
    // 🛡️ FAPI 2.0 / H-2 (Holder Binding) ტესტური სცენარები
    // =========================================================================

    [Fact(DisplayName = "🛡️ H-2: Presentation MUST fail when issuer SD-JWT is missing required cnf.jkt")]
    public async Task VerifyPresentationAsync_WhenIssuerCnfMissing_ReturnsFailure()
    {
        // Arrange - ვქმნით გამცემ ტოკენს cnf.jkt-ს გარეშე
        var issuerJwt = CreateIssuerJwt(null);
        var disclosure = CreateDisclosure("salt-1", "name", "John");
        var kbJwt = CreateKeyBindingJwt(_ecdsa, issuerJwt, [disclosure], "sentinel-api");
        var presentation = $"{issuerJwt}~{disclosure}~{kbJwt}";

        _validatorMock
            .Setup(x => x.ValidateIssuerTokenAsync(It.IsAny<string>(), "sentinel-api", It.IsAny<CancellationToken>()))
            .ReturnsAsync(SdJwtIssuerTokenValidationResult.Success(new JsonWebToken(issuerJwt)));

        // Act
        var result = await _sut.VerifyPresentationAsync(presentation, "sentinel-api");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().Contain("missing required cnf.jkt");
    }

    [Fact(DisplayName = "🛡️ H-2: Presentation MUST fail when holder key thumbprint does not match issuer cnf.jkt")]
    public async Task VerifyPresentationAsync_WhenHolderKeyMismatched_ReturnsFailure()
    {
        // Arrange - გამცემ ტოკენში ვწერთ სხვა გასაღების თამბპრინტს
        var issuerJwt = CreateIssuerJwt("mismatched-holder-jkt-value");
        var disclosure = CreateDisclosure("salt-1", "name", "John");
        var kbJwt = CreateKeyBindingJwt(_ecdsa, issuerJwt, [disclosure], "sentinel-api");
        var presentation = $"{issuerJwt}~{disclosure}~{kbJwt}";

        _validatorMock
            .Setup(x => x.ValidateIssuerTokenAsync(It.IsAny<string>(), "sentinel-api", It.IsAny<CancellationToken>()))
            .ReturnsAsync(SdJwtIssuerTokenValidationResult.Success(new JsonWebToken(issuerJwt)));

        // Act
        var result = await _sut.VerifyPresentationAsync(presentation, "sentinel-api");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Error.Should().Contain("doesn't match issuer's cnf.jkt");
    }

    [Fact(DisplayName = "✅ H-2: Presentation succeeds when key binding complies and cnf.jkt matches")]
    public async Task VerifyPresentationAsync_WhenKeyBindingComplies_ReturnsSuccess()
    {
        // Arrange - ვქმნით ვალიდურ და სინქრონიზებულ ტოკენებს
        var holderJkt = ComputeJwkThumbprint(_ecdsa);
        var issuerJwt = CreateIssuerJwt(holderJkt);
        var disclosure = CreateDisclosure("salt-1", "name", "John");
        var kbJwt = CreateKeyBindingJwt(_ecdsa, issuerJwt, [disclosure], "sentinel-api");
        var presentation = $"{issuerJwt}~{disclosure}~{kbJwt}";

        _validatorMock
            .Setup(x => x.ValidateIssuerTokenAsync(It.IsAny<string>(), "sentinel-api", It.IsAny<CancellationToken>()))
            .ReturnsAsync(SdJwtIssuerTokenValidationResult.Success(new JsonWebToken(issuerJwt)));

        // Act
        var result = await _sut.VerifyPresentationAsync(presentation, "sentinel-api");

        // Assert
        result.IsValid.Should().BeTrue();
        result.Principal.Should().NotBeNull();
        result.Principal!.FindFirst("name")?.Value.Should().Be("John");
    }

    // --- კრიპტოგრაფიული დამხმარე მეთოდები ტესტებისთვის ---

    private string CreateIssuerJwt(string? holderJkt = null)
    {
        var handler = new JsonWebTokenHandler();
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "test-user",
            ["_sd_alg"] = "sha-256",
            ["_sd"] = new[] { ComputeDisclosureDigest(CreateDisclosure("salt-1", "name", "John")) }
        };

        if (holderJkt != null)
        {
            claims["cnf"] = new Dictionary<string, string> { ["jkt"] = holderJkt };
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "https://localhost:8443/realms/sentinel",
            Audience = "sentinel-api",
            Claims = claims,
            Expires = DateTime.UtcNow.AddMinutes(10),
            SigningCredentials = new SigningCredentials(_securityKey, SecurityAlgorithms.EcdsaSha256)
        };

        return handler.CreateToken(descriptor);
    }

    private static string CreateKeyBindingJwt(ECDsa holderKey, string issuerJwt, string[] disclosures, string audience)
    {
        var handler = new JsonWebTokenHandler();
        var key = new ECDsaSecurityKey(holderKey);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);

        var jwkHeader = new Dictionary<string, string>
        {
            ["kty"] = jwk.Kty!,
            ["crv"] = jwk.Crv!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Audience = audience,
            Claims = new Dictionary<string, object>
            {
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ["sd_hash"] = ComputeSdHash(issuerJwt, disclosures)
            },
            Expires = DateTime.UtcNow.AddMinutes(10),
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object> { ["jwk"] = jwkHeader }
        };

        return handler.CreateToken(descriptor);
    }

    private static string CreateDisclosure(string salt, string claimName, string claimValue)
    {
        var json = JsonSerializer.Serialize(new object[] { salt, claimName, claimValue });
        return Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(json));
    }

    private static string ComputeDisclosureDigest(string disclosure) =>
        Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(disclosure)));

    private static string ComputeSdHash(string issuerJwt, string[] disclosures)
    {
        var presentationNoKb = $"{issuerJwt}~{string.Join("~", disclosures)}";
        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(presentationNoKb)));
    }

    private static string ComputeJwkThumbprint(ECDsa holderKey)
    {
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(holderKey));
        var canonical = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["crv"] = jwk.Crv!,
            ["kty"] = jwk.Kty!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        });
        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}
