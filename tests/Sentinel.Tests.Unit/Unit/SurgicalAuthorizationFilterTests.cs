using System.Security.Claims;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.Domain.Auth.Rar;
using Sentinel.RAR;
using Sentinel.Sample.MinimalApi.Endpoints;
using Sentinel.Sample.MinimalApi.Filters;

namespace Sentinel.Tests.Unit.Unit;

public sealed class SurgicalAuthorizationFilterTests
{
    private const string FinanceTransferType = "urn:sentinel:finance:transfer";

    [Fact(DisplayName = "🧪 Filter: Valid RAR bounds must proceed to next handler")]
    public async Task InvokeAsync_WithValidRar_ProceedsToNext()
    {
        // Arrange
        var mockRarValidator = new Mock<IRarValidator>();
        mockRarValidator
            .Setup(x => x.ValidateByType(It.IsAny<AuthorizationDetail[]>(), FinanceTransferType, It.IsAny<string>()))
            .Returns(RarValidationResult.Success(new AuthorizationDetail(FinanceTransferType)));

        var filter =
            new SurgicalAuthorizationFilter(mockRarValidator.Object, NullLogger<SurgicalAuthorizationFilter>.Instance);

        var httpContext = new DefaultHttpContext();
        httpContext.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-123")], "Test"));

        var request = new TransferRequest("txn-123", 500.00m, "USD", "acc-456");
        var context = new TestEndpointFilterInvocationContext(httpContext, request);

        var nextCalled = false;
        EndpointFilterDelegate next = _ =>
        {
            nextCalled = true;
            return ValueTask.FromResult<object?>(TypedResults.Ok());
        };

        // Act
        var result = await filter.InvokeAsync(context, next);

        // Assert
        nextCalled.Should().BeTrue("Valid RAR validation should allow request pipeline continuation");
        mockRarValidator.Verify(
            x => x.ValidateByType(It.IsAny<AuthorizationDetail[]>(), FinanceTransferType, It.IsAny<string>()),
            Times.Once);
    }

    [Fact(DisplayName = "🧪 Filter: Mismatched RAR bounds must return 403 ProblemDetails")]
    public async Task InvokeAsync_WithInvalidRar_Returns403Problem()
    {
        // Arrange
        var mockRarValidator = new Mock<IRarValidator>();
        mockRarValidator
            .Setup(x => x.ValidateByType(It.IsAny<AuthorizationDetail[]>(), FinanceTransferType, It.IsAny<string>()))
            .Returns(RarValidationResult.Failure("Cryptographic bounds exceeded: Maximum allowed transfer is $500"));

        var filter =
            new SurgicalAuthorizationFilter(mockRarValidator.Object, NullLogger<SurgicalAuthorizationFilter>.Instance);

        var httpContext = new DefaultHttpContext();
        httpContext.User = new ClaimsPrincipal(new ClaimsIdentity());

        var request = new TransferRequest("txn-123", 100000.00m, "USD", "acc-456");
        var context = new TestEndpointFilterInvocationContext(httpContext, request);

        EndpointFilterDelegate next = _ => ValueTask.FromResult<object?>(TypedResults.Ok());

        // Act
        var result = await filter.InvokeAsync(context, next);

        // Assert
        var problemResult = result.Should().BeOfType<ProblemHttpResult>().Subject;
        problemResult.StatusCode.Should().Be(StatusCodes.Status403Forbidden);
        problemResult.ProblemDetails.Type.Should().Be("/errors/authorization-bounds-exceeded");
        problemResult.ProblemDetails.Detail.Should()
            .Be("Cryptographic bounds exceeded: Maximum allowed transfer is $500");
    }

    // --- Test helper context (Native AOT compatible) ---
    private sealed class TestEndpointFilterInvocationContext : EndpointFilterInvocationContext
    {
        public TestEndpointFilterInvocationContext(HttpContext httpContext, params object?[] arguments)
        {
            HttpContext = httpContext;
            Arguments = arguments;
        }

        public override HttpContext HttpContext { get; }
        public override IList<object?> Arguments { get; }

        public override T GetArgument<T>(int index) => (T)Arguments[index]!;
    }
}
