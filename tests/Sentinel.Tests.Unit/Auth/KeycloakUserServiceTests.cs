using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Domain.Users;
using Sentinel.Infrastructure.Auth.Services;
using Sentinel.Security.Abstractions.Results;
using Xunit;
using FluentAssertions;

namespace Sentinel.Tests.Unit.Auth;

/// <summary>
/// Keycloak User Service Tests (Identity Creation and Location Header Parsing)
///
/// When Keycloak Admin API creates a user, it returns HTTP 201 Created with a Location header
/// containing the newly created user's UUID. Vulnerabilities in parsing this header can lead to:
///
/// 1. Information Enumeration: If a 409 Conflict response is not properly mapped, attackers
///    can enumerate existing users by observing different error messages.
///
/// 2. UUID Extraction Failures: Malformed Location headers could cause exceptions that leak
///    the raw header to logs/monitoring, or fail to create user sessions.
///
/// 3. Path Traversal: If the UUID isn't extracted from the exact last segment, an attacker
///    might inject path components that get reflected.
///
/// This test suite ensures:
/// - 409 Conflict is mapped to a generic security error (no user enumeration)
/// - Location header parsing is robust for various URL structures
/// - Invalid responses fail gracefully without exceptions
/// </summary>
public sealed class KeycloakUserServiceTests
{
    private static readonly ILogger<KeycloakUserService> NullLogger = NullLogger<KeycloakUserService>.Instance;

    [Fact]
    public async Task CreateUserInternalAsync_WhenConflict_ReturnsIdentityConflict()
    {
        // 409 Conflict = user with that email/username already exists
        // CRITICAL: We must NOT return the actual reason (user enumeration prevention)
        var handler = new StubHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.Conflict));

        var sut = new KeycloakUserService(
            new HttpClient(handler) { BaseAddress = new Uri("https://idp/admin/realms/test") },
            NullLogger);

        var registration = new UserRegistration(
            email: "test@example.com",
            username: "testuser",
            consent: ConsentInfo.Create(true, "v1", "192.168.1.1", DateTimeOffset.UtcNow));

        var result = await sut.CreateUserInternalAsync(registration, "password", CancellationToken.None);

        result.IsSuccess.Should().BeFalse("409 Conflict should be treated as failure");
        result.ErrorMessage.Should().Be(SecurityErrors.IdentityConflictMessage, "Error message should not reveal if user exists");
    }

    [Fact]
    public async Task CreateUserInternalAsync_WhenServerError_ReturnsIdentityCreationFailed()
    {
        // 500 or other server errors
        var handler = new StubHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.InternalServerError)
            {
                Content = new StringContent("Internal database error: SELECT * FROM SECRETS")
            });

        var sut = new KeycloakUserService(
            new HttpClient(handler) { BaseAddress = new Uri("https://idp/admin/realms/test") },
            NullLogger);

        var registration = new UserRegistration(
            email: "test@example.com",
            username: "testuser",
            consent: ConsentInfo.Create(true, "v1", "192.168.1.1", DateTimeOffset.UtcNow));

        var result = await sut.CreateUserInternalAsync(registration, "password", CancellationToken.None);

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Be(SecurityErrors.IdentityCreationFailedMessage);
        // Error details from server should NOT be passed to client
        result.ErrorMessage.Should().NotContain("database");
        result.ErrorMessage.Should().NotContain("SECRETS");
    }

    [Fact]
    public async Task CreateUserInternalAsync_WhenSuccess_ExtractsUserIdFromLocationHeader()
    {
        // RFC 7231: 201 Created responses SHOULD include Location header with the new resource URI
        var expectedUserId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        var handler = new StubHttpMessageHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Created);
            response.Headers.Location = new Uri($"https://idp/admin/realms/test/users/{expectedUserId}");
            return response;
        });

        var sut = new KeycloakUserService(
            new HttpClient(handler) { BaseAddress = new Uri("https://idp/admin/realms/test") },
            NullLogger);

        var registration = new UserRegistration(
            email: "test@example.com",
            username: "testuser",
            consent: ConsentInfo.Create(true, "v1", "192.168.1.1", DateTimeOffset.UtcNow));

        var result = await sut.CreateUserInternalAsync(registration, "password", CancellationToken.None);

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().Be(expectedUserId, "Location header UUID should be extracted");
    }

    [Fact]
    public async Task CreateUserInternalAsync_WhenLocationHeaderMissing_ReturnsFailed()
    {
        // 201 Created without Location header is a protocol violation
        var handler = new StubHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.Created)
            {
                // No Location header set
            });

        var sut = new KeycloakUserService(
            new HttpClient(handler) { BaseAddress = new Uri("https://idp/admin/realms/test") },
            NullLogger);

        var registration = new UserRegistration(
            email: "test@example.com",
            username: "testuser",
            consent: ConsentInfo.Create(true, "v1", "192.168.1.1", DateTimeOffset.UtcNow));

        var result = await sut.CreateUserInternalAsync(registration, "password", CancellationToken.None);

        result.IsSuccess.Should().BeFalse("Missing Location header should be treated as failure");
        result.ErrorMessage.Should().Be(SecurityErrors.IdentityCreationFailedMessage);
    }

    [Fact]
    public async Task CreateUserInternalAsync_WhenLocationHeaderHasTrailingSlash_ExtractsUserIdCorrectly()
    {
        // Keycloak might return Location with or without trailing slash
        var expectedUserId = "uuid-12345-67890";
        var handler = new StubHttpMessageHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Created);
            response.Headers.Location = new Uri($"https://idp/admin/realms/test/users/{expectedUserId}/");
            return response;
        });

        var sut = new KeycloakUserService(
            new HttpClient(handler) { BaseAddress = new Uri("https://idp/admin/realms/test") },
            NullLogger);

        var registration = new UserRegistration(
            email: "test@example.com",
            username: "testuser",
            consent: ConsentInfo.Create(true, "v1", "192.168.1.1", DateTimeOffset.UtcNow));

        var result = await sut.CreateUserInternalAsync(registration, "password", CancellationToken.None);

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().Be(expectedUserId);
    }

    [Fact]
    public async Task CreateUserInternalAsync_WhenLocationHeaderUriEncoded_ExtractsCorrectly()
    {
        // UUID extraction from URI-encoded Location header
        var expectedUserId = "uuid-with-special%20chars";
        var handler = new StubHttpMessageHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Created);
            // Location header might contain encoded characters
            response.Headers.Location = new Uri($"https://idp/admin/realms/test/users/{expectedUserId}");
            return response;
        });

        var sut = new KeycloakUserService(
            new HttpClient(handler) { BaseAddress = new Uri("https://idp/admin/realms/test") },
            NullLogger);

        var registration = new UserRegistration(
            email: "test@example.com",
            username: "testuser",
            consent: ConsentInfo.Create(true, "v1", "192.168.1.1", DateTimeOffset.UtcNow));

        var result = await sut.CreateUserInternalAsync(registration, "password", CancellationToken.None);

        result.IsSuccess.Should().BeTrue();
        // UUID should be extracted (may be URI-decoded by the Uri class)
        result.Value.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task CreateUserInternalAsync_WhenBadRequest_ReturnsGenericError()
    {
        // 400 Bad Request shouldn't leak request details
        var handler = new StubHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent("Invalid field 'email': Expected RFC 5321 format")
            });

        var sut = new KeycloakUserService(
            new HttpClient(handler) { BaseAddress = new Uri("https://idp/admin/realms/test") },
            NullLogger);

        var registration = new UserRegistration(
            email: "malformed@",
            username: "testuser",
            consent: ConsentInfo.Create(true, "v1", "192.168.1.1", DateTimeOffset.UtcNow));

        var result = await sut.CreateUserInternalAsync(registration, "password", CancellationToken.None);

        result.IsSuccess.Should().BeFalse();
        // Client should not see validation details from Keycloak
        result.ErrorMessage.Should().NotContain("RFC 5321");
        result.ErrorMessage.Should().NotContain("Invalid field");
    }

    /// <summary>
    /// Stubs HttpMessageHandler for testing without actual HTTP calls.
    /// </summary>
    private sealed class StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var response = responseFactory(request);
            return Task.FromResult(response);
        }
    }
}
