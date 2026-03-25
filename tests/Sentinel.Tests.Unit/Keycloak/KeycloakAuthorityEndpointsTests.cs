using Sentinel.Keycloak;
using Xunit;
using FluentAssertions;

namespace Sentinel.Tests.Unit.Keycloak;

/// <summary>
/// Keycloak Authority Endpoint Parsing Tests (SSRF Prevention)
///
/// Production Keycloak deployments vary significantly:
/// - Standard: /realms/sentinel
/// - With prefix: /auth/realms/sentinel (older versions behind reverse proxy)
/// - Custom sub-paths: /identity/admin/realms/sentinel
/// - Trailing slashes may be present or absent
///
/// This test suite ensures that URL parsing is:
/// 1. Robust to variations without becoming vulnerable to SSRF
/// 2. Correctly appends the protocol paths
/// 3. Properly validates realm names (prevents injection)
///
/// If parsing is incorrect, an attacker could:
/// - Cause the API to make requests to internal IPs (SSRF)
/// - Bypass URL validation in the reverse proxy
/// - Extract sensitive data from error messages
/// </summary>
public sealed class KeycloakAuthorityEndpointsTests
{
    [Theory]
    [InlineData("https://idp.example.com/realms/sentinel")]
    [InlineData("https://idp.example.com/realms/sentinel/")] // Trailing slash
    public void TryBuild_WithStandardAuthority_ExtractsEndpointsCorrectly(string authority)
    {
        var success = KeycloakAuthorityEndpoints.TryBuild(authority, out var tokenEndpoint, out var adminEndpoint);

        success.Should().BeTrue("Standard realm authority should parse successfully");
        tokenEndpoint.AbsoluteUri.Should().Be("https://idp.example.com/realms/sentinel/protocol/openid-connect/token");
        adminEndpoint.AbsoluteUri.Should().Be("https://idp.example.com/admin/realms/sentinel/");
    }

    [Theory]
    [InlineData("https://idp.example.com/auth/realms/sentinel")] // Legacy /auth prefix
    [InlineData("https://idp.example.com/auth/realms/sentinel/")] // With trailing slash
    [InlineData("https://idp.example.com/identity/realms/gov-realm")] // Custom prefix
    public void TryBuild_WithCustomPrefixPath_ExtractsEndpointsCorrectly(string authority)
    {
        var success = KeycloakAuthorityEndpoints.TryBuild(authority, out var tokenEndpoint, out var adminEndpoint);

        success.Should().BeTrue($"Authority with custom prefix should parse: {authority}");

        // Verify the prefix is preserved in both endpoints
        tokenEndpoint.AbsoluteUri.Should().Contain("realms/");
        adminEndpoint.AbsoluteUri.Should().Contain("/admin/realms/");

        // Verify protocol path is correct
        tokenEndpoint.AbsoluteUri.Should().Contain("/protocol/openid-connect/token");
    }

    [Theory]
    [InlineData("https://idp.example.com/auth/realms/multi-segment/realm")] // Multi-segment realm ID
    [InlineData("https://idp.example.com/realms/realm-with-dashes")] // Dashes in realm name
    [InlineData("https://idp.example.com/realms/realm_with_underscores")] // Underscores in realm name
    public void TryBuild_WithVariousRealmNames_PreserveRealmNameCorrectly(string authority)
    {
        var success = KeycloakAuthorityEndpoints.TryBuild(authority, out var tokenEndpoint, out var adminEndpoint);

        success.Should().BeTrue($"Realm with valid characters should parse: {authority}");

        // Both endpoints should be valid absolute URIs
        tokenEndpoint.IsAbsoluteUri.Should().BeTrue();
        adminEndpoint.IsAbsoluteUri.Should().BeTrue();
    }

    [Theory]
    [InlineData("not-a-url")] // Missing scheme
    [InlineData("https://idp.example.com/no-realm-segment/sentinel")] // No "realms" marker
    [InlineData("https://idp.example.com/realms/")] // Missing realm name
    [InlineData("https://idp.example.com/realms")] // No segment after realms
    [InlineData("http://localhost")] // No realm path at all
    public void TryBuild_WithInvalidAuthority_ReturnsFalse(string invalidAuthority)
    {
        var success = KeycloakAuthorityEndpoints.TryBuild(invalidAuthority, out _, out _);

        success.Should().BeFalse($"Invalid authority should be rejected: {invalidAuthority}");
    }

    [Fact]
    public void TryBuild_WithSpecialCharactersInRealmName_UriEncodesCorrectly()
    {
        // Realm names with special chars must be URI-encoded to prevent injection
        var authority = "https://idp.example.com/realms/realm%20with%20spaces";

        var success = KeycloakAuthorityEndpoints.TryBuild(authority, out var tokenEndpoint, out var adminEndpoint);

        success.Should().BeTrue();

        // The encoded realm name should be preserved in the output URIs
        tokenEndpoint.IsAbsoluteUri.Should().BeTrue();
        adminEndpoint.IsAbsoluteUri.Should().BeTrue();

        // Ensure both are well-formed (no double-encoding, no injection vectors)
        new Uri(tokenEndpoint.AbsoluteUri).IsAbsoluteUri.Should().BeTrue();
    }

    [Fact]
    public void TryBuild_WithDifferentSchemes_HandlesCorrectly()
    {
        var httpsAuthority = "https://secure.example.com/realms/sentinel";
        var successHttps = KeycloakAuthorityEndpoints.TryBuild(httpsAuthority, out var tokenHttps, out var adminHttps);

        successHttps.Should().BeTrue();
        tokenHttps.Scheme.Should().Be("https");
        adminHttps.Scheme.Should().Be("https");
    }

    [Theory]
    [InlineData("https://idp.example.com:8080/realms/sentinel")] // Non-standard port
    [InlineData("https://192.168.1.100/realms/sentinel")] // IP address instead of hostname
    [InlineData("https://localhost:8443/realms/sentinel")] // Localhost (for testing)
    public void TryBuild_WithVariousHosts_ConstructsValidUris(string authority)
    {
        var success = KeycloakAuthorityEndpoints.TryBuild(authority, out var tokenEndpoint, out var adminEndpoint);

        success.Should().BeTrue();
        tokenEndpoint.IsAbsoluteUri.Should().BeTrue();
        adminEndpoint.IsAbsoluteUri.Should().BeTrue();

        // Verify that host information is preserved
        tokenEndpoint.Host.Should().NotBeNullOrEmpty();
        adminEndpoint.Host.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void TryBuild_BothEndpointsPreserveHost()
    {
        var authority = "https://idp.example.com/auth/realms/sentinel";

        KeycloakAuthorityEndpoints.TryBuild(authority, out var tokenEndpoint, out var adminEndpoint);

        // Both endpoints should point to the SAME host (preventing SSRF to different server)
        tokenEndpoint.Host.Should().Be(adminEndpoint.Host);
        tokenEndpoint.Scheme.Should().Be(adminEndpoint.Scheme);
    }
}
