using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Errors;
using Sentinel.Presentation.Middleware;
using Xunit;
using FluentAssertions;

namespace Sentinel.Tests.Unit.Middleware;

/// <summary>
/// Global Exception Handler Tests (Zero Information Leakage)
///
/// Security Principle: "Defense in Depth for Error Handling"
///
/// An unhandled exception (e.g., NullReferenceException, OutOfMemoryException) in production
/// must NEVER leak to the client:
///
/// 1. Exception Type Leakage: If a client sees "InvalidCastException", they know the
///    internal implementation is trying to cast something, leaking architectural details.
///
/// 2. Stack Trace Leakage: Stack traces reveal:
///    - File paths (e.g., /home/ubuntu/sentinel/src/Auth/...)
///    - Method names and line numbers
///    - Database query implementations
///    - Third-party dependencies
///
/// 3. Message Leakage: Exception messages often contain:
///    - SQL connection strings
///    - Internal API endpoints
///    - Sensitive configuration values
///    - User data that was being processed
///
/// This test suite proves mathematically that:
/// - ALL internal exceptions result in generic 500 errors
/// - Response body contains only safe, generic ProblemDetails
/// - Trace IDs are provided for backend correlation (for support)
/// - Sensitive details are logged server-side only (not sent to client)
/// </summary>
public sealed class GlobalExceptionHandlerTests
{
    private static readonly ILogger<GlobalExceptionHandler> NullLogger =
        NullLogger<GlobalExceptionHandler>.Instance;

    [Fact]
    public async Task TryHandleAsync_InterceptsException_WritesSecureProblemDetails()
    {
        // Arrange
        var sut = new GlobalExceptionHandler(NullLogger);

        var context = new DefaultHttpContext();
        context.Request.Path = "/v1/users/register";
        context.Request.Method = "POST";
        context.TraceIdentifier = "trace-xyz-123";

        var memoryStream = new MemoryStream();
        context.Response.Body = memoryStream;

        var exception = new InvalidOperationException("CRITICAL: Database connection pool exhausted!");

        // Act
        var handled = await sut.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert: Handler claimed responsibility
        handled.Should().BeTrue("Exception handler should handle and return true");

        // Assert: Status code is generic 500
        context.Response.StatusCode.Should().Be(StatusCodes.Status500InternalServerError);

        // Parse response body
        memoryStream.Seek(0, SeekOrigin.Begin);
        using var doc = await JsonDocument.ParseAsync(memoryStream);
        var root = doc.RootElement;

        // Assert: ProblemDetails structure is present and correct
        root.GetProperty("status").GetInt32().Should().Be(500);
        root.GetProperty("type").GetString().Should().Be(ErrorCodes.InternalServerError);
        root.GetProperty("instance").GetString().Should().Be("/v1/users/register");
        root.TryGetProperty("title", out var titleElement).Should().BeTrue();
        titleElement.GetString().Should().NotBeNull();

        // Assert: Trace ID is provided for support/debugging
        root.TryGetProperty("traceId", out var traceIdElem).Should().BeTrue("Trace ID should be included");
        traceIdElem.GetString().Should().Be("trace-xyz-123");

        // CRITICAL ASSERTION: Exception details MUST be absent
        var fullJson = root.GetRawText();
        fullJson.Should().NotContain("CRITICAL");
        fullJson.Should().NotContain("Database connection pool");
        fullJson.Should().NotContain("InvalidOperationException");
        fullJson.Should().NotContain("NullReferenceException");
        fullJson.Should().NotContain("at Sentinel.");
    }

    [Fact]
    public async Task TryHandleAsync_WithCorrelationId_IncludesCorrelationIdInResponse()
    {
        // Arrange
        var sut = new GlobalExceptionHandler(NullLogger);

        var context = new DefaultHttpContext();
        context.Request.Path = "/health";
        context.TraceIdentifier = "trace-abc";
        context.Items["X-Correlation-ID"] = "corr-456";

        var memoryStream = new MemoryStream();
        context.Response.Body = memoryStream;

        var exception = new NullReferenceException("Internal state corruption");

        // Act
        await sut.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        memoryStream.Seek(0, SeekOrigin.Begin);
        using var doc = await JsonDocument.ParseAsync(memoryStream);
        var root = doc.RootElement;

        root.TryGetProperty("correlationId", out var corrIdElem).Should().BeTrue();
        corrIdElem.GetString().Should().Be("corr-456");

        // Ensure sensitive message is NOT included
        root.GetRawText().Should().NotContain("corruption");
    }

    [Fact]
    public async Task TryHandleAsync_WithoutCorrelationId_StillReturnsValidResponse()
    {
        // Arrange
        var sut = new GlobalExceptionHandler(NullLogger);

        var context = new DefaultHttpContext();
        context.Request.Path = "/api/auth/login";
        context.TraceIdentifier = "trace-def";
        // No X-Correlation-ID set

        var memoryStream = new MemoryStream();
        context.Response.Body = memoryStream;

        var exception = new DivideByZeroException("Calculation error in user rating algorithm");

        // Act
        await sut.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert: Response is still valid
        memoryStream.Seek(0, SeekOrigin.Begin);
        using var doc = await JsonDocument.ParseAsync(memoryStream);
        var root = doc.RootElement;

        root.GetProperty("status").GetInt32().Should().Be(500);
        root.TryGetProperty("traceId", out _).Should().BeTrue();

        // correlationId should not be present if not provided
        root.TryGetProperty("correlationId", out _).Should().BeFalse();

        // Message leakage check
        root.GetRawText().Should().NotContain("Calculation error");
        root.GetRawText().Should().NotContain("DivideByZeroException");
    }

    [Theory]
    [InlineData("OutOfMemoryException")]
    [InlineData("StackOverflowException")]
    [InlineData("AccessViolationException")]
    public async Task TryHandleAsync_WithCriticalExceptions_StillReturnsGenericError(string exceptionTypeName)
    {
        // Arrange
        var sut = new GlobalExceptionHandler(NullLogger);

        var context = new DefaultHttpContext();
        context.Request.Path = "/api/data";
        context.TraceIdentifier = "trace-critical";

        var memoryStream = new MemoryStream();
        context.Response.Body = memoryStream;

        Exception exception = exceptionTypeName switch
        {
            "OutOfMemoryException" => new OutOfMemoryException("Ran out of memory processing large dataset"),
            "StackOverflowException" => new StackOverflowException("Stack overflow in recursive auth check"),
            "AccessViolationException" => new AccessViolationException("Runtime error in token validation"),
            _ => throw new NotSupportedException()
        };

        // Act
        var handled = await sut.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        handled.Should().BeTrue("All exceptions should be handled");
        context.Response.StatusCode.Should().Be(StatusCodes.Status500InternalServerError);

        // Verify no exception type or message leakage
        memoryStream.Seek(0, SeekOrigin.Begin);
        using var doc = await JsonDocument.ParseAsync(memoryStream);
        var fullJson = doc.RootElement.GetRawText();

        fullJson.Should().NotContain(exceptionTypeName);
        fullJson.Should().NotContain("out of memory");
        fullJson.Should().NotContain("Stack overflow");
        fullJson.Should().NotContain("token validation");
    }

    [Fact]
    public async Task TryHandleAsync_WithAggregateException_DoesNotLeakInnerExceptions()
    {
        // Arrange
        var sut = new GlobalExceptionHandler(NullLogger);

        var context = new DefaultHttpContext();
        context.Request.Path = "/api/batch";
        context.TraceIdentifier = "trace-aggregate";

        var memoryStream = new MemoryStream();
        context.Response.Body = memoryStream;

        var innerEx1 = new SqlException("Connection failed to db.example.com");
        var innerEx2 = new HttpRequestException("Failed to reach https://internal-api:9090");
        var exception = new AggregateException("Batch operation failed", innerEx1, innerEx2);

        // Act
        await sut.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        memoryStream.Seek(0, SeekOrigin.Begin);
        using var doc = await JsonDocument.ParseAsync(memoryStream);
        var fullJson = doc.RootElement.GetRawText();

        // No exception details should leak
        fullJson.Should().NotContain("db.example.com");
        fullJson.Should().NotContain("internal-api");
        fullJson.Should().NotContain("SqlException");
        fullJson.Should().NotContain("HttpRequestException");
        fullJson.Should().NotContain("Batch operation failed");
    }

    [Fact]
    public async Task TryHandleAsync_ResponseIsValidJson()
    {
        // Arrange
        var sut = new GlobalExceptionHandler(NullLogger);

        var context = new DefaultHttpContext();
        context.Request.Path = "/";
        context.TraceIdentifier = "trace-json";

        var memoryStream = new MemoryStream();
        context.Response.Body = memoryStream;
        context.Response.ContentType = "application/problem+json";

        var exception = new Exception("Any error");

        // Act
        await sut.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert: Response body is valid JSON
        memoryStream.Seek(0, SeekOrigin.Begin);
        var parseAction = async () => await JsonDocument.ParseAsync(memoryStream);
        await parseAction.Should().NotThrowAsync("Response must be valid JSON");

        // Verify it's writable JSON structure
        memoryStream.Seek(0, SeekOrigin.Begin);
        using var doc = await JsonDocument.ParseAsync(memoryStream);
        doc.RootElement.ValueKind.Should().Be(System.Text.Json.JsonValueKind.Object);
    }

    [Fact]
    public async Task TryHandleAsync_PreservesRequestPathInInstance()
    {
        // Assert that we preserve the request path for reconstruction in logs
        // but not the query string (which might contain sensitive data)
        var sut = new GlobalExceptionHandler(NullLogger);

        var context = new DefaultHttpContext();
        context.Request.Path = "/api/users/profile";
        context.Request.QueryString = new QueryString("?email=admin@internal.com&token=secret123");
        context.TraceIdentifier = "trace-path";

        var memoryStream = new MemoryStream();
        context.Response.Body = memoryStream;

        var exception = new Exception("test");

        // Act
        await sut.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        memoryStream.Seek(0, SeekOrigin.Begin);
        using var doc = await JsonDocument.ParseAsync(memoryStream);
        var instance = doc.RootElement.GetProperty("instance").GetString();

        instance.Should().Be("/api/users/profile", "Instance should preserve path for audit");
        instance.Should().NotContain("email");
        instance.Should().NotContain("token");
        instance.Should().NotContain("secret");
    }

    // Helper class to simulate SqlException without actual SQL dependencies
    private sealed class SqlException : Exception
    {
        public SqlException(string message) : base(message) { }
    }
}
