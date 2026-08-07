// Sentinel Security API - FAPI 2.0 Compliant

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Options;
using Sentinel.Application.Common.Abstractions;
using Sentinel.AspNetCore.Endpoints;
using Sentinel.AspNetCore.Errors;
using Sentinel.DPoP;
using Sentinel.Infrastructure.Auth;
using Sentinel.Security.Abstractions.Identity;

namespace Sentinel.Tests.Integration.Integration;

[Collection("Sentinel Integration")]
public sealed class ChangePasswordIntegrationTests : IClassFixture<SentinelApiFactory>
{
    private readonly Mock<ISessionBlacklistCache> _blacklistCacheMock = new();
    private readonly WebApplicationFactory<Program> _factory;
    private readonly Mock<IIdentityProvider> _identityProviderMock = new();
    private readonly Mock<IAuthRevocationService> _revocationServiceMock = new();

    public ChangePasswordIntegrationTests(SentinelApiFactory factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureTestServices(services =>
            {
                services.AddSingleton(_identityProviderMock.Object);
                services.AddSingleton(_revocationServiceMock.Object);
                services.AddSingleton(_blacklistCacheMock.Object);

                var testPasswordOptions = Options.Create(new PasswordPolicyOptions
                {
                    MinimumLength = 12,
                    RequireDigit = true,
                    RequireUppercase = true,
                    RequireLowercase = true,
                    RequireNonAlphanumeric = true,
                    MinimumEntropyBits = 50.0
                });
                services.AddSingleton(testPasswordOptions);
                services.AddSingleton<IPasswordStrengthValidator, EnterprisePasswordStrengthValidator>();

                services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
                {
                    options.TokenValidationParameters.IssuerSigningKey = TestTokenIssuer.AuthoritySecurityKey;
                    options.TokenValidationParameters.ValidateIssuerSigningKey = true;
                    options.TokenValidationParameters.ValidIssuer = "https://localhost:8443/realms/sentinel";
                    options.TokenValidationParameters.ValidAudience = "sentinel-api";
                    options.RequireHttpsMetadata = false;
                    options.ConfigurationManager = null;

                    var originalOnMessageReceived = options.Events.OnMessageReceived;

                    options.Events.OnMessageReceived = async context =>
                    {
                        var authHeader = context.Request.Headers.Authorization.ToString();
                        if (authHeader.StartsWith("TestScheme ", StringComparison.OrdinalIgnoreCase))
                        {
                            context.Token = authHeader["TestScheme ".Length..].Trim();
                        }

                        if (originalOnMessageReceived != null)
                        {
                            await originalOnMessageReceived(context);
                        }
                    };
                });
            });
        });
    }

    private static string MintTestToken(string subject, string username, string sid, string acr, string jkt)
    {
        var handler = new JsonWebTokenHandler();
        var now = DateTimeOffset.UtcNow;
        var exp = now.AddMinutes(5);

        var claims = new Dictionary<string, object>
        {
            [JwtRegisteredClaimNames.Sub] = subject,
            [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString("N"),
            [JwtRegisteredClaimNames.Iat] = now.ToUnixTimeSeconds(),
            [JwtRegisteredClaimNames.Exp] = exp.ToUnixTimeSeconds(),
            ["preferred_username"] = username,
            ["email"] = $"{username}@sentinel.ge",
            ["sid"] = sid,
            ["acr"] = acr,
            ["scope"] = "profile",
            ["realm_access.roles"] = JsonSerializer.Serialize(new[] { "user" }),
            ["cnf"] = new Dictionary<string, string> { ["jkt"] = jkt },
            ["auth_time"] = now.ToUnixTimeSeconds()
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "https://localhost:8443/realms/sentinel",
            Audience = "sentinel-api",
            Claims = claims,
            Expires = exp.UtcDateTime,
            SigningCredentials =
                new SigningCredentials(TestTokenIssuer.AuthoritySecurityKey, SecurityAlgorithms.EcdsaSha256)
        };

        return handler.CreateToken(descriptor);
    }

    private static (string AccessToken, string DpopProof, Dictionary<string, string> Jwk) CreateBoundCredentials(
        string subject, string username, string sid, string acr, string requestUrl)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(ecdsa));

        var jwkObject = new Dictionary<string, string>
        {
            ["crv"] = jwk.Crv!,
            ["kty"] = jwk.Kty!,
            ["x"] = jwk.X!,
            ["y"] = jwk.Y!
        };

        var thumbprintComputer = new DpopThumbprintComputer();
        using var jwkDoc = JsonDocument.Parse(JsonSerializer.Serialize(jwkObject));
        var jkt = thumbprintComputer.Compute(jwkDoc.RootElement);

        var accessToken = MintTestToken(subject, username, sid, acr, jkt);

        var dpopProof = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["jti"] = Guid.NewGuid().ToString("N"),
                ["htm"] = "POST",
                ["htu"] = requestUrl,
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            },
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha256),
            TokenType = "dpop+jwt",
            AdditionalHeaderClaims = new Dictionary<string, object> { ["jwk"] = jwkObject }
        });

        return (accessToken, dpopProof, jwkObject);
    }

    [Fact(DisplayName =
        "✅ Integration: Entering a strong password updates the database and revokes sessions (204 NoContent)")]
    public async Task ChangePassword_WithValidStrongPassword_ExecutesFullFlowAndReturns204()
    {
        // Arrange
        var client = _factory.CreateClient();

        var requestUrl = new Uri(client.BaseAddress!, "/v1/auth/change-password").ToString();
        var (accessToken, dpopProof, _) =
            CreateBoundCredentials("user-secure-123", "enterprise_user", "session-active-456", "acr3", requestUrl);

        var requestPayload = new AuthEndpoints.ChangePasswordRequest("Strong$SecurePass9513");

        _identityProviderMock
            .Setup(x => x.UpdatePasswordAsync("enterprise_user", requestPayload.NewPassword,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        _revocationServiceMock
            .Setup(x => x.RevokeAllSessionsAsync("user-secure-123", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        _blacklistCacheMock
            .Setup(x => x.BlacklistSessionAsync("session-active-456", It.IsAny<TimeSpan>(),
                It.IsAny<CancellationToken>()))
            .Returns(() => Task.CompletedTask);

        // Act
        using var request = new HttpRequestMessage(HttpMethod.Post, requestUrl)
        {
            Content = JsonContent.Create(requestPayload)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
        request.Headers.Add("DPoP", dpopProof);
        request.Headers.Add("Idempotency-Key", Guid.NewGuid().ToString());

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        _identityProviderMock.Verify(
            x => x.UpdatePasswordAsync("enterprise_user", requestPayload.NewPassword, It.IsAny<CancellationToken>()),
            Times.Once);
        _revocationServiceMock.Verify(x => x.RevokeAllSessionsAsync("user-secure-123", It.IsAny<CancellationToken>()),
            Times.Once);
        _blacklistCacheMock.Verify(
            x => x.BlacklistSessionAsync("session-active-456", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact(DisplayName =
        "❌ Integration: Entering a weak password blocks the request and nothing is written to the database (400 BadRequest)")]
    public async Task ChangePassword_WithWeakPassword_Returns400ProblemDetails()
    {
        // Arrange
        var client = _factory.CreateClient();

        var requestUrl = new Uri(client.BaseAddress!, "/v1/auth/change-password").ToString();
        var (accessToken, dpopProof, _) =
            CreateBoundCredentials("user-secure-123", "enterprise_user", "session-active-456", "acr3", requestUrl);

        var requestPayload = new AuthEndpoints.ChangePasswordRequest("weak123");

        // Act
        using var request = new HttpRequestMessage(HttpMethod.Post, requestUrl)
        {
            Content = JsonContent.Create(requestPayload)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
        request.Headers.Add("DPoP", dpopProof);
        request.Headers.Add("Idempotency-Key", Guid.NewGuid().ToString());

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var problem = await response.Content.ReadFromJsonAsync<ProblemDetails>(TestContext.Current.CancellationToken);
        Assert.NotNull(problem);
        Assert.Equal(ErrorCodes.WeakPassword, problem.Type);

        _identityProviderMock.Verify(
            x => x.UpdatePasswordAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }
}
