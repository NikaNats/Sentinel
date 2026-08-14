using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Sentinel.Contracts.Shared;

namespace Sentinel.Contracts.Keycloak;

/// <summary>
///     CONTRACT: Keycloak Admin REST API Response Shapes.
///
///     Sentinel's session revocation, user management and federation services
///     parse these JSON shapes. A field rename in a Keycloak update breaks them
///     silently.
///
///     Constitution Ref: §II.6 (Session Management), §II.7 (Multi-Tenancy).
/// </summary>
[Collection(KeycloakContractCollection.Name)]
[ContractVersion("CONTRACT-001", "1.0", Target = "Keycloak 26.6.4")]
public sealed class AdminApiContractTests(KeycloakContractFixture fixture)
{
    private readonly KeycloakContractFixture _fixture = fixture;

    [Fact(DisplayName = "CONTRACT: GET /users returns schema-valid user representations")]
    public async Task AdminApi_GetUsers_ReturnsExpectedUserSchema()
    {
        var response = await _fixture.SendAdminAsync(HttpMethod.Get, "/users", cancellationToken: TestContext.Current.CancellationToken);
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        using var document = JsonDocument.Parse(content);

        document.RootElement.ValueKind.Should().Be(JsonValueKind.Array, "GET /users must return a JSON array");

        if (document.RootElement.GetArrayLength() > 0)
        {
            var schema = EmbeddedResourceReader.Read("admin-user.schema.json");
            foreach (var user in document.RootElement.EnumerateArray())
            {
                var result = SchemaValidator.Validate(schema, user.GetRawText());
                result.IsValid.Should().BeTrue(
                    $"user drifted from the pinned schema:{Environment.NewLine}{string.Join(Environment.NewLine, result.Errors)}");
            }
        }
        else
        {
            // The fixture provisions contract-user on boot; an empty list means
            // discoverability contract changed (user listing MUST include direct grants users).
            document.RootElement.GetArrayLength().Should().BeGreaterThan(0,
                "contract user must be findable via GET /users");
        }
    }

    [Fact(DisplayName = "CONTRACT: user sessions describe id/start/lastAccess/ipAddress")]
    public async Task AdminApi_GetUserSessions_ReturnsExpectedSessionSchema()
    {
        await GetUserSessionAsyncAssertingSuccess();
        var userId = await FindUserUserIdAsync();

        var response = await _fixture.SendAdminAsync(HttpMethod.Get, $"/users/{userId}/sessions", cancellationToken: TestContext.Current.CancellationToken);
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        using var document = JsonDocument.Parse(content);

        document.RootElement.ValueKind.Should().Be(JsonValueKind.Array);
        document.RootElement.GetArrayLength().Should().BeGreaterThan(0,
            "the password-grant login must create a real session (contract discovery)");

        var session = document.RootElement[0];
        foreach (var field in new[] { "id", "start", "lastAccess", "ipAddress" })
        {
            session.TryGetProperty(field, out _).Should().BeTrue(
                $"session MUST contain '{field}' (KeycloakAuthRevocationService depends on it)");
        }
    }

    [Fact(DisplayName = "CONTRACT: POST /users returns 201 + Location header")]
    public async Task AdminApi_CreateUser_Returns201WithLocationHeader()
    {
        var username = $"contract-test-{Guid.NewGuid():N}";
        var response = await _fixture.SendAdminAsync(HttpMethod.Post, "/users", UserPayload(username), cancellationToken: TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Created, "POST /users must return 201");
        response.Headers.Location.Should().NotBeNull("Location header MUST carry the new user URL");
        response.Headers.Location!.ToString().Should().Contain("/users/", "Location must point at the user resource");
    }

    [Fact(DisplayName = "CONTRACT: DELETE /users/{id} returns 204 No Content")]
    public async Task AdminApi_DeleteUser_Returns204NoContent()
    {
        var userId = await CreateUserReturningIdAsync();

        var response = await _fixture.SendAdminAsync(HttpMethod.Delete, $"/users/{userId}", cancellationToken: TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.NoContent,
            "KeycloakUserService.DeleteUserAsync depends on 204");
    }

    [Fact(DisplayName = "CONTRACT: identity providers endpoint returns an array")]
    public async Task AdminApi_GetIdentityProviders_ReturnsArray()
    {
        var response = await _fixture.SendAdminAsync(HttpMethod.Get, "/identity-provider/instances", cancellationToken: TestContext.Current.CancellationToken);
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        document.RootElement.ValueKind.Should().Be(JsonValueKind.Array,
            "KeycloakFederationService depends on an array");
    }

    [Fact(DisplayName = "CONTRACT: admin API rejects anonymous requests with 401")]
    public async Task AdminApi_WithoutAuthToken_Returns401()
    {
        var response = await _fixture.HttpClient.GetAsync($"{_fixture.AdminBaseUrl}/users", TestContext.Current.CancellationToken);
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "Admin API MUST reject unauthenticated requests");
    }

    // ─── Helpers ────────────────────────────────────────────────────────

    private static StringContent UserPayload(string username) => new(
        JsonSerializer.Serialize(
            new KeycloakContractUserPayload(
                username,
                true,
                true,
                $"{username}@contract-test.local",
                []),
            KeycloakContractJsonContext.Default.KeycloakContractUserPayload),
        Encoding.UTF8, "application/json");

    private async Task<string> CreateUserReturningIdAsync()
    {
        var username = $"contract-del-{Guid.NewGuid():N}";
        var response = await _fixture.SendAdminAsync(HttpMethod.Post, "/users", UserPayload(username));
        response.StatusCode.Should().Be(HttpStatusCode.Created);
        return response.Headers.Location!.ToString().Split('/').Last();
    }

    private async Task<string> FindUserUserIdAsync()
    {
        var response = await _fixture.SendAdminAsync(
            HttpMethod.Get, $"/users?username=contract-user&exact=true", cancellationToken: TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        document.RootElement.GetArrayLength().Should().BeGreaterThan(0, "contract-user must exist");
        return document.RootElement[0].GetProperty("id").GetString()!;
    }

    /// <summary>
    ///     Performs the interactive login so a user session actually exists.
    ///     ROPC is prohibited by the realm client policy (§II.1), so sessions
    ///     only come from the authorization-code flow.
    /// </summary>
    private async Task GetUserSessionAsync()
    {
        await _fixture.LoginInteractiveAsync();
    }

    private async Task GetUserSessionAsyncAssertingSuccess()
    {
        await GetUserSessionAsync();
    }
}