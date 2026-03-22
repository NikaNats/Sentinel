namespace Sentinel.Tests.SSF;

/// <summary>
/// Tests for SsfEventProcessor SET token processing.
/// </summary>
public sealed class SsfEventProcessorTests
{
    [Fact]
    public async Task ProcessAsync_WhenTokenEmpty_ReturnsFail()
    {
        var processor = new SsfEventProcessor(
            new MockSsfTokenValidator(),
            MockSessionBlacklistCache.Create(),
            new MockAuthRevocationService());

        var result = await processor.ProcessAsync("");

        Assert.False(result.IsSuccess);
    }

    [Fact]
    public async Task ProcessAsync_WhenValidationFails_ReturnsFail()
    {
        var validator = new MockSsfTokenValidator { ShouldFail = true };
        var processor = new SsfEventProcessor(
            validator,
            MockSessionBlacklistCache.Create(),
            new MockAuthRevocationService());

        var result = await processor.ProcessAsync("invalid-token");

        Assert.False(result.IsSuccess);
    }

    [Fact]
    public async Task ProcessAsync_WhenValidationSucceeds_ReturnsSuccess()
    {
        var validator = new MockSsfTokenValidator { ShouldFail = false };
        var processor = new SsfEventProcessor(
            validator,
            MockSessionBlacklistCache.Create(),
            new MockAuthRevocationService());

        var result = await processor.ProcessAsync("valid-token");

        Assert.True(result.IsSuccess);
    }
}
