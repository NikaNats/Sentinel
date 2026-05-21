using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Sentinel.AspNetCore.Middleware;
using Sentinel.Security.Abstractions.DPoP;
using Sentinel.Security.Abstractions.Nonce;
using Sentinel.Security.Abstractions.Results;

namespace Sentinel.Tests.Unit;

public sealed class DpopValidationMiddlewareTests
{
    [Fact]
    public async Task InvokeAsync_WhenDownstreamThrows_DoesNotConsumeOrRotateNonce()
    {
        var validatorMock = CreateValidatorSuccessMock();
        var nonceStoreMock = new Mock<IDpopNonceStore>(MockBehavior.Strict);
        var thumbprintComputerMock = new Mock<IDpopThumbprintComputer>(MockBehavior.Strict);

        const string thumbprint = "thumbprint-1";
        nonceStoreMock
            .Setup(x => x.GetNonceAsync(thumbprint, It.IsAny<CancellationToken>()))
            .ReturnsAsync("old-nonce");

        thumbprintComputerMock
            .Setup(x => x.Compute(It.IsAny<System.Text.Json.JsonElement>()))
            .Returns(thumbprint);

        RequestDelegate next = _ => throw new InvalidOperationException("downstream-failure");
        var middleware = new DpopValidationMiddleware(
            next,
            thumbprintComputerMock.Object);

        var context = CreateDpopContext();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            middleware.InvokeAsync(context, validatorMock.Object, nonceStoreMock.Object));

        nonceStoreMock.Verify(x => x.GetNonceAsync(thumbprint, It.IsAny<CancellationToken>()), Times.Once);
        nonceStoreMock.Verify(
            x => x.ConsumeNonceIfMatchesAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
        nonceStoreMock.Verify(
            x => x.SetNonceAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task InvokeAsync_WhenResponseSuccessful_DoesNotMutateNonceBeforeCommit()
    {
        var validatorMock = CreateValidatorSuccessMock();
        var nonceStoreMock = new Mock<IDpopNonceStore>(MockBehavior.Strict);
        var thumbprintComputerMock = new Mock<IDpopThumbprintComputer>(MockBehavior.Strict);

        const string thumbprint = "thumbprint-2";
        const string expectedNonce = "old-nonce";
        const string nextNonce = "next-nonce";

        nonceStoreMock
            .Setup(x => x.GetNonceAsync(thumbprint, It.IsAny<CancellationToken>()))
            .ReturnsAsync(expectedNonce);
        nonceStoreMock
            .Setup(x => x.ConsumeNonceIfMatchesAsync(thumbprint, expectedNonce, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        nonceStoreMock
            .Setup(x => x.SetNonceAsync(
                thumbprint,
                nextNonce,
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        thumbprintComputerMock
            .Setup(x => x.Compute(It.IsAny<System.Text.Json.JsonElement>()))
            .Returns(thumbprint);

        validatorMock
            .Setup(x => x.ValidateAsync(It.IsAny<DpopValidationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(SecurityResultFactory.Create(new DpopValidationSuccess(nextNonce, thumbprint)));

        RequestDelegate next = _ => Task.CompletedTask;
        var middleware = new DpopValidationMiddleware(
            next,
            thumbprintComputerMock.Object);

        var context = CreateDpopContext();

        await middleware.InvokeAsync(context, validatorMock.Object, nonceStoreMock.Object);

        // In unit-test host, response commit hooks are not executed like Kestrel/TestServer.
        // This assertion verifies sequencing: nonce state is not mutated during request execution.
        nonceStoreMock.Verify(x => x.ConsumeNonceIfMatchesAsync(thumbprint, expectedNonce, It.IsAny<CancellationToken>()),
            Times.Never);
        nonceStoreMock.Verify(
            x => x.SetNonceAsync(thumbprint, nextNonce, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task InvokeAsync_WhenResponseIsServerError_DoesNotConsumeOrRotateNonce()
    {
        var validatorMock = CreateValidatorSuccessMock();
        var nonceStoreMock = new Mock<IDpopNonceStore>(MockBehavior.Strict);
        var thumbprintComputerMock = new Mock<IDpopThumbprintComputer>(MockBehavior.Strict);

        const string thumbprint = "thumbprint-3";
        nonceStoreMock
            .Setup(x => x.GetNonceAsync(thumbprint, It.IsAny<CancellationToken>()))
            .ReturnsAsync("old-nonce");

        thumbprintComputerMock
            .Setup(x => x.Compute(It.IsAny<System.Text.Json.JsonElement>()))
            .Returns(thumbprint);

        RequestDelegate next = ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status500InternalServerError;
            return Task.CompletedTask;
        };

        var middleware = new DpopValidationMiddleware(
            next,
            thumbprintComputerMock.Object);

        var context = CreateDpopContext();

        await middleware.InvokeAsync(context, validatorMock.Object, nonceStoreMock.Object);
        await context.Response.WriteAsync("error");

        nonceStoreMock.Verify(
            x => x.ConsumeNonceIfMatchesAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
        nonceStoreMock.Verify(
            x => x.SetNonceAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()),
            Times.Never);
    }

    private static Mock<IDpopProofValidator> CreateValidatorSuccessMock()
    {
        var validatorMock = new Mock<IDpopProofValidator>(MockBehavior.Strict);
        validatorMock
            .Setup(x => x.ValidateAsync(It.IsAny<DpopValidationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(SecurityResultFactory.Create(new DpopValidationSuccess("next-nonce", "thumbprint")));
        return validatorMock;
    }

    private static DefaultHttpContext CreateDpopContext()
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("api.example.com");
        context.Request.Path = "/resource";
        context.Request.Method = HttpMethods.Get;
        context.Request.Headers.Authorization = "DPoP access-token";
        context.Request.Headers["DPoP"] = CreateProofWithJwkHeader();
        return context;
    }

    private static string CreateProofWithJwkHeader()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signingKey = new ECDsaSecurityKey(ecdsa);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(signingKey);

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["jti"] = Guid.NewGuid().ToString("N"),
                ["htm"] = "GET",
                ["htu"] = "https://api.example.com/resource",
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            },
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.EcdsaSha256),
            TokenType = "dpop+jwt",
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = new Dictionary<string, string>
                {
                    ["kty"] = jwk.Kty!,
                    ["crv"] = jwk.Crv!,
                    ["x"] = jwk.X!,
                    ["y"] = jwk.Y!
                }
            }
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }
}
