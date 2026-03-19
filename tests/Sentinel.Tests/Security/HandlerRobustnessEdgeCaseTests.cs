using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.Application.Auth;
using Sentinel.Application.Auth.Interfaces;
using Sentinel.Application.Auth.Models;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Controllers;
using Sentinel.Domain.Auth;

namespace Sentinel.Tests.Security;

public sealed class HandlerRobustnessEdgeCaseTests
{
    [Fact]
    public async Task RegisterUserHandler_WhenRequestIsNull_ThrowsArgumentFailure()
    {
        var sut = new RegisterUserHandler(
            Mock.Of<ICaptchaService>(),
            Mock.Of<IKeycloakAdminService>(),
            Mock.Of<IEmailService>(),
            Mock.Of<IEmailVerificationTokenStore>(),
            Mock.Of<IPasswordStrengthValidator>());

        Func<Task> act = async () => await sut.HandleAsync(null!, "ip", CancellationToken.None);

        await act.Should().ThrowAsync<NullReferenceException>();
    }

    [Fact]
    public async Task ForgotPasswordHandler_WhenRequestIsNull_ThrowsArgumentFailure()
    {
        var sut = new ForgotPasswordHandler(
            Mock.Of<IKeycloakAdminService>(),
            Mock.Of<IResetTokenProvider>(),
            Mock.Of<IEmailService>(),
            Mock.Of<ICaptchaService>(),
            NullLogger<ForgotPasswordHandler>.Instance);

        Func<Task> act = async () => await sut.HandleAsync(null!, CancellationToken.None);

        await act.Should().ThrowAsync<NullReferenceException>();
    }

    [Fact]
    public async Task ResetPasswordHandler_WhenRequestIsNull_ThrowsArgumentFailure()
    {
        var sut = new ResetPasswordHandler(
            Mock.Of<IResetTokenProvider>(),
            Mock.Of<IKeycloakAdminService>(),
            Mock.Of<IJtiReplayCache>(),
            Mock.Of<IAuthRevocationService>());

        Func<Task> act = async () => await sut.HandleAsync(null!, CancellationToken.None);

        await act.Should().ThrowAsync<NullReferenceException>();
    }

    [Fact]
    public async Task TokenExchangeController_WhenMalformedProviderOrToken_ReturnsBadRequest()
    {
        var controller = new TokenExchangeController(Mock.Of<ITokenExchangeService>())
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };
        controller.Request.Headers["DPoP"] = "proof";

        var response = await controller.ExchangeExternalToken(
            new TokenExchangeController.TokenExchangeRequest(" ", " ", " "),
            CancellationToken.None);

        response.Should().BeOfType<BadRequestObjectResult>();
    }
}
