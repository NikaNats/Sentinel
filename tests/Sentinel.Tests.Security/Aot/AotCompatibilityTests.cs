using System.Text.Json;
using FluentAssertions;
using Sentinel.Application;
using Sentinel.Application.Auth.Models;
using Sentinel.Domain.Auth.Rar;

namespace Sentinel.Tests.Security.Aot;

/// <summary>
///     Native AOT Trim-Safety Compliance Tests
///     This test suite exercises every JSON-bound model used in the security pipeline
///     with the ApplicationJsonContext. In a Native AOT environment with aggressive trimming,
///     any model missing from the source-generated context will throw NotSupportedException
///     or InvalidOperationException at runtime.
///     Why This Matters:
///     - Native AOT strips reflection and unused code at compile time
///     - If a model isn't in the JSON context, JsonSerializer has no metadata to deserialize it
///     - Traditional reflection-based serialization doesn't work in AOT
///     - This test must pass BEFORE shipping to production (non-negotiable)
///     Architect's Note: This is a "compile-time gate"; failure means the binary is broken.
///     Every security-critical model MUST be tested here.
/// </summary>
public sealed class AotCompatibilityTests
{
    /// <summary>
    ///     Test: TokenExchangeResult (OAuth2 token response) can round-trip through JSON.
    ///     Security Impact: If TokenExchangeResult cannot deserialize in AOT, token
    ///     exchanges will fail at runtime with cryptic exceptions. Critical path.
    /// </summary>
    [Fact]
    public void Verify_TokenExchangeResult_IsTrimSafe()
    {
        // Arrange: Create instance representing a successful token exchange
        var instance = new TokenExchangeResult
        {
            AccessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
            TokenType = "DPoP",
            ExpiresIn = 3600,
            RefreshToken = "refresh_token_...",
            Scope = "openid profile email"
        };

        // Act: Serialize with source-generated context
        var json = JsonSerializer.Serialize(
            instance,
            typeof(TokenExchangeResult),
            ApplicationJsonContext.Default);

        // Act: Deserialize with source-generated context
        var deserialized = JsonSerializer.Deserialize(
            json,
            typeof(TokenExchangeResult),
            ApplicationJsonContext.Default);

        // Assert
        deserialized.Should().NotBeNull("Deserialization must succeed in AOT");
        deserialized.Should().BeOfType<TokenExchangeResult>();

        var result = (TokenExchangeResult)deserialized!;
        result.AccessToken.Should().Be(instance.AccessToken,
            "Token data must survive serialization round-trip");
        result.TokenType.Should().Be("DPoP");
        result.ExpiresIn.Should().Be(3600);
    }

    /// <summary>
    ///     Test: AuthorizationDetail (RAR) can round-trip through JSON.
    ///     Security Impact: Rich Authorization Requests require deserialization of
    ///     AuthorizationDetail objects. AOT trimming must preserve this type.
    /// </summary>
    [Fact]
    public void Verify_AuthorizationDetail_IsTrimSafe()
    {
        // Arrange: Create financial authorization detail
        var instance = new AuthorizationDetail("urn:openbanking:params:acr:value:financial")
        {
            TransactionId = "txn_2026_001",
            Amount = 150.50m,
            Currency = "USD"
        };

        // Act: Serialize
        var json = JsonSerializer.Serialize(
            instance,
            typeof(AuthorizationDetail),
            ApplicationJsonContext.Default);

        // Act: Deserialize
        var deserialized = JsonSerializer.Deserialize(
            json,
            typeof(AuthorizationDetail),
            ApplicationJsonContext.Default);

        // Assert
        deserialized.Should().NotBeNull();
        deserialized.Should().BeOfType<AuthorizationDetail>();

        var detail = (AuthorizationDetail)deserialized!;
        detail.Type.Should().Be("urn:openbanking:params:acr:value:financial");
        detail.TransactionId.Should().Be("txn_2026_001");
        detail.Amount.Should().Be(150.50m,
            "Decimal precision must be preserved (critical for financial auth)");
        detail.Currency.Should().Be("USD");
    }

    /// <summary>
    ///     Test: Array of AuthorizationDetail can round-trip.
    ///     Security Impact: Multiple authorization details in a single request.
    ///     If array type isn't in context, batch requests fail.
    /// </summary>
    [Fact]
    public void Verify_AuthorizationDetailArray_IsTrimSafe()
    {
        // Arrange: Create array with multiple details
        var instances = new[]
        {
            new AuthorizationDetail("urn:openbanking:params:acr:value:financial")
            {
                TransactionId = "txn_first",
                Amount = 100m,
                Currency = "USD"
            },
            new AuthorizationDetail("urn:openbanking:params:acr:value:financial")
            {
                TransactionId = "txn_second",
                Amount = 200m,
                Currency = "EUR"
            }
        };

        // Act: Serialize array
        var json = JsonSerializer.Serialize(
            instances,
            typeof(AuthorizationDetail[]),
            ApplicationJsonContext.Default);

        // Act: Deserialize array
        var deserialized = JsonSerializer.Deserialize(
            json,
            typeof(AuthorizationDetail[]),
            ApplicationJsonContext.Default);

        // Assert
        deserialized.Should().NotBeNull();
        deserialized.Should().BeOfType<AuthorizationDetail[]>();

        var details = (AuthorizationDetail[])deserialized!;
        details.Should().HaveCount(2,
            "Array length must be preserved");
        details[0].TransactionId.Should().Be("txn_first");
        details[1].Amount.Should().Be(200m);
    }

    /// <summary>
    ///     Test: Dictionary&lt;string, object&gt; (generic claim/property bags) can round-trip.
    ///     Security Impact: Many OAuth2 flows use untyped dictionaries for additional parameters.
    ///     If Dictionary type isn't in context, claim transformation fails.
    /// </summary>
    [Fact]
    public void Verify_DictionaryStringObject_IsTrimSafe()
    {
        // Arrange: Create untyped dictionary (common in OAuth2 responses)
        var instance = new Dictionary<string, object>
        {
            ["access_token"] = "token_value",
            ["token_type"] = "DPoP",
            ["expires_in"] = 3600,
            ["custom_claim"] = 12345,
            ["nested"] = new Dictionary<string, object>
            {
                ["key"] = "value"
            }
        };

        // Act: Serialize
        var json = JsonSerializer.Serialize(
            instance,
            typeof(Dictionary<string, object>),
            ApplicationJsonContext.Default);

        // Act: Deserialize
        var deserialized = JsonSerializer.Deserialize(
            json,
            typeof(Dictionary<string, object>),
            ApplicationJsonContext.Default);

        // Assert
        deserialized.Should().NotBeNull();
        deserialized.Should().BeOfType<Dictionary<string, object>>();

        var dict = (Dictionary<string, object>)deserialized!;
        dict.Should().ContainKey("access_token",
            "Token field must survive serialization");
        dict["token_type"].Should().BeOfType<JsonElement>();
        ((JsonElement)dict["token_type"]).GetString().Should().Be("DPoP");
        dict["expires_in"].Should().BeOfType<JsonElement>();
        ((JsonElement)dict["expires_in"]).GetInt32().Should().Be(3600);
    }

    /// <summary>
    ///     Test: Verify ApplicationJsonContext is properly initialized (not null).
    ///     Security Impact: Source generators sometimes fail silently if not properly
    ///     configured. This catches that at test time, not production time.
    /// </summary>
    [Fact]
    public void Verify_ApplicationJsonContext_IsInitialized()
    {
        // Arrange & Act
        var context = ApplicationJsonContext.Default;

        // Assert
        context.Should().NotBeNull(
            "ApplicationJsonContext.Default must be initialized (check partial class implementation)");

        // Verify context has expected type info
        var typeInfo = context.GetTypeInfo(typeof(TokenExchangeResult));
        typeInfo.Should().NotBeNull(
            "TokenExchangeResult type info must be available in context");
    }

    /// <summary>
    ///     Test: Verify no exceptions are thrown during JSON operations.
    ///     Security Impact: NotSupportedException during deserialization indicates
    ///     trimmed type. This test catches that before production.
    /// </summary>
    [Fact]
    public void Verify_NoNotSupportedExceptions_OnTrimSafeTypes()
    {
        // Arrange: Collection of types that MUST be trim-safe
        var typesToVerify = new[]
        {
            typeof(TokenExchangeResult),
            typeof(AuthorizationDetail),
            typeof(AuthorizationDetail[]),
            typeof(Dictionary<string, object>)
        };

        var testInstances = new object[]
        {
            new TokenExchangeResult { AccessToken = "test", TokenType = "Bearer", ExpiresIn = 3600 },
            new AuthorizationDetail("test") { TransactionId = "txn", Amount = 1m, Currency = "USD" },
            new[] { new AuthorizationDetail("test") { TransactionId = "txn", Amount = 1m, Currency = "USD" } },
            new Dictionary<string, object> { ["key"] = "value" }
        };

        // Act & Assert: No NotSupportedException thrown
        for (var i = 0; i < typesToVerify.Length; i++)
        {
            var type = typesToVerify[i];
            var instance = testInstances[i];

            // This should NOT throw NotSupportedException (trimmed type)
            var json = JsonSerializer.Serialize(
                instance,
                type,
                ApplicationJsonContext.Default);

            json.Should().NotBeNullOrWhiteSpace(
                $"Type {type.Name} must serialize successfully in AOT");

            // Deserialization should also not throw
            var deserialized = JsonSerializer.Deserialize(
                json,
                type,
                ApplicationJsonContext.Default);

            deserialized.Should().NotBeNull(
                $"Type {type.Name} must deserialize successfully in AOT");
        }
    }

    /// <summary>
    ///     Integration Test: Full OAuth2 Token Exchange flow with AOT constraints.
    ///     Scenario: Client exchanges authorization code for access token.
    ///     All objects must be trim-safe for the full flow to work.
    /// </summary>
    [Fact]
    public void Verify_FullTokenExchangeFlow_IsTrimSafe()
    {
        // Arrange: Simulate token exchange response
        var tokenResponse = new TokenExchangeResult
        {
            AccessToken = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImstMSJ9...",
            TokenType = "DPoP",
            ExpiresIn = 3600,
            RefreshToken = "refresh_...",
            Scope = "openid profile"
            // Additional claims
        };

        var authDetails = new[]
        {
            new AuthorizationDetail("urn:openbanking:params:acr:value:financial")
            {
                TransactionId = "transactions_flow_123",
                Amount = 50_000m,
                Currency = "USD"
            }
        };

        // Act 1: Serialize token response
        var tokenJson = JsonSerializer.Serialize(
            tokenResponse,
            typeof(TokenExchangeResult),
            ApplicationJsonContext.Default);

        // Act 2: Serialize authorization details
        var detailsJson = JsonSerializer.Serialize(
            authDetails,
            typeof(AuthorizationDetail[]),
            ApplicationJsonContext.Default);

        // Act 3: Deserialize back
        var tokenDeserialized = JsonSerializer.Deserialize(
            tokenJson,
            typeof(TokenExchangeResult),
            ApplicationJsonContext.Default);

        var detailsDeserialized = JsonSerializer.Deserialize(
            detailsJson,
            typeof(AuthorizationDetail[]),
            ApplicationJsonContext.Default);

        // Assert: Full flow works
        tokenDeserialized.Should().NotBeNull();
        detailsDeserialized.Should().NotBeNull();

        var token = (TokenExchangeResult)tokenDeserialized!;
        var details = (AuthorizationDetail[])detailsDeserialized!;

        token.AccessToken.Should().NotBeEmpty("Token must be present");
        token.TokenType.Should().Be("DPoP");
        details.Should().HaveCount(1);
        details[0].Amount.Should().Be(50_000m, "Financial amount must survive round-trip");
    }
}
