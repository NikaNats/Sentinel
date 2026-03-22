namespace Sentinel.Tests.Shared;

/// <summary>
/// Mock TimeProvider for deterministic test time handling.
/// Allows tests to control the current time without actual delays.
/// </summary>
public sealed class FakeTimeProvider : TimeProvider
{
    private DateTimeOffset _currentTime;

    /// <summary>
    /// Initializes a new instance with a fixed time.
    /// </summary>
    public FakeTimeProvider(DateTimeOffset fixedTime)
    {
        _currentTime = fixedTime;
    }

    /// <summary>
    /// Gets or sets the current time (for advancing time in tests).
    /// </summary>
    public DateTimeOffset CurrentTime
    {
        get => _currentTime;
        set => _currentTime = value;
    }

    /// <inheritdoc/>
    public override TimeZoneInfo LocalTimeZone => TimeZoneInfo.Utc;

    /// <inheritdoc/>
    public override DateTimeOffset GetUtcNow() => _currentTime;

    /// <summary>
    /// Advances the current time by the specified duration.
    /// </summary>
    public void Advance(TimeSpan duration) => _currentTime = _currentTime.Add(duration);

    /// <summary>
    /// Resets to a specific time.
    /// </summary>
    public void SetTime(DateTimeOffset newTime) => _currentTime = newTime;
}
