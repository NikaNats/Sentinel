using System.Net;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Sentinel.Domain.Users;
using Sentinel.Keycloak.Services;
using Sentinel.Security.Abstractions.Results;
using Sentinel.Security.Diagnostics;

namespace Sentinel.Tests.Unit.Auth;

public sealed class KeycloakUserServiceTests
{
    private static readonly ILogger<KeycloakUserService> NullLogger = NullLogger<KeycloakUserService>.Instance;
    private static readonly Mock<IPrivacyPreservingHasher> PrivacyHasherMock = new(MockBehavior.Strict);

    static KeycloakUserServiceTests()
    {
        PrivacyHasherMock
            .Setup(x => x.HashIpAddress(It.IsAny<IPAddress>()))
            .Returns((IPAddress ip) => $"hashed-{ip}");
    }

    [Fact]
    public async Task CreateUserInternalAsync_WhenConflict_ReturnsIdentityConflict()
    {
        var handler = new StubHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.Conflict));

        var sut = new KeycloakUserService(
            new HttpClient(handler) { BaseAddress = new Uri("https://idp/admin/realms/test") },
            PrivacyHasherMock.Object,
            NullLogger);

        var registration = new UserRegistration(
            "test@example.com",
            "testuser",
            ConsentInfo.Create(true, "v1", "hashed-192.168.1.1",
                DateTimeOffset.UtcNow));

        var result = await sut.CreateUserInternalAsync(registration, "password", CancellationToken.None);

        result.IsSuccess.Should().BeFalse("409 Conflict should be treated as failure");
        result.ErrorMessage.Should().Be(SecurityErrors.IdentityConflictMessage,
            "Error message should not reveal if user exists");
    }

    [Fact]
    public async Task CreateUserInternalAsync_WhenServerError_ReturnsIdentityCreationFailed()
    {
        var handler = new StubHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.InternalServerError)
            {
                Content = new StringContent("Internal database error: SELECT * FROM SECRETS")
            });

        var sut = new KeycloakUserService(
            new HttpClient(handler) { BaseAddress = new Uri("https://idp/admin/realms/test") },
            PrivacyHasherMock.Object,
            NullLogger);

        var registration = new UserRegistration(
            "test@example.com",
            "testuser",
            ConsentInfo.Create(true, "v1", "hashed-192.168.1.1",
                DateTimeOffset.UtcNow));

        var result = await sut.CreateUserInternalAsync(registration, "password", CancellationToken.None);

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Be(SecurityErrors.IdentityCreationFailedMessage);
        result.ErrorMessage.Should().NotContain("database");
        result.ErrorMessage.Should().NotContain("SECRETS");
    }

    [Fact]
    public async Task CreateUserInternalAsync_WhenSuccess_ExtractsUserIdFromLocationHeader()
    {
        var expectedUserId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        var handler = new StubHttpMessageHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Created);
            response.Headers.Location = new Uri($"https://idp/admin/realms/test/users/{expectedUserId}");
            return response;
        });

        var sut = new KeycloakUserService(
            new HttpClient(handler) { BaseAddress = new Uri("https://idp/admin/realms/test") },
            PrivacyHasherMock.Object,
            NullLogger);

        var registration = new UserRegistration(
            "test@example.com",
            "testuser",
            ConsentInfo.Create(true, "v1", "hashed-192.168.1.1",
                DateTimeOffset.UtcNow));

        var result = await sut.CreateUserInternalAsync(registration, "password", CancellationToken.None);

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().Be(expectedUserId, "Location header UUID should be extracted");
    }

    [Fact]
    public async Task CreateUserInternalAsync_WhenLocationHeaderMissing_ReturnsFailed()
    {
        var handler = new StubHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.Created));

        var sut = new KeycloakUserService(
            new HttpClient(handler) { BaseAddress = new Uri("https://idp/admin/realms/test") },
            PrivacyHasherMock.Object,
            NullLogger);

        var registration = new UserRegistration(
            "test@example.com",
            "testuser",
            ConsentInfo.Create(true, "v1", "hashed-192.168.1.1",
                DateTimeOffset.UtcNow));

        var result = await sut.CreateUserInternalAsync(registration, "password", CancellationToken.None);

        result.IsSuccess.Should().BeFalse("Missing Location header should be treated as failure");
        result.ErrorMessage.Should().Be(SecurityErrors.IdentityCreationFailedMessage);
    }

    [Fact]
    public async Task CreateUserInternalAsync_WhenLocationHeaderHasTrailingSlash_ExtractsUserIdCorrectly()
    {
        var expectedUserId = "uuid-12345-67890";
        var handler = new StubHttpMessageHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Created);
            response.Headers.Location = new Uri($"https://idp/admin/realms/test/users/{expectedUserId}/");
            return response;
        });

        var sut = new KeycloakUserService(
            new HttpClient(handler) { BaseAddress = new Uri("https://idp/admin/realms/test") },
            PrivacyHasherMock.Object,
            NullLogger);

        var registration = new UserRegistration(
            "test@example.com",
            "testuser",
            ConsentInfo.Create(true, "v1", "hashed-192.168.1.1",
                DateTimeOffset.UtcNow));

        var result = await sut.CreateUserInternalAsync(registration, "password", CancellationToken.None);

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().Be(expectedUserId);
    }

    [Fact]
    public async Task CreateUserInternalAsync_WhenLocationHeaderUriEncoded_ExtractsCorrectly()
    {
        var expectedUserId = "uuid-with-special%20chars";
        var handler = new StubHttpMessageHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Created);
            response.Headers.Location = new Uri($"https://idp/admin/realms/test/users/{expectedUserId}");
            return response;
        });

        var sut = new KeycloakUserService(
            new HttpClient(handler) { BaseAddress = new Uri("https://idp/admin/realms/test") },
            PrivacyHasherMock.Object,
            NullLogger);

        var registration = new UserRegistration(
            "test@example.com",
            "testuser",
            ConsentInfo.Create(true, "v1", "hashed-192.168.1.1",
                DateTimeOffset.UtcNow));

        var result = await sut.CreateUserInternalAsync(registration, "password", CancellationToken.None);

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task CreateUserInternalAsync_WhenBadRequest_ReturnsGenericError()
    {
        var handler = new StubHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent("Invalid field 'email': Expected RFC 5321 format")
            });

        var sut = new KeycloakUserService(
            new HttpClient(handler) { BaseAddress = new Uri("https://idp/admin/realms/test") },
            PrivacyHasherMock.Object,
            NullLogger);

        var registration = new UserRegistration(
            "malformed@",
            "testuser",
            ConsentInfo.Create(true, "v1", "hashed-192.168.1.1",
                DateTimeOffset.UtcNow));

        var result = await sut.CreateUserInternalAsync(registration, "password", CancellationToken.None);

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().NotContain("RFC 5321");
        result.ErrorMessage.Should().NotContain("Invalid field");
    }

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
