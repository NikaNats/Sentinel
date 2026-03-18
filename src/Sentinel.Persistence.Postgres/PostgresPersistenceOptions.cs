namespace Sentinel.Persistence.Postgres;

public sealed class PostgresPersistenceOptions
{
    public int CommandTimeoutSeconds { get; set; } = 30;

    public int MaxRetryCount { get; set; } = 3;

    public bool EnableSensitiveDataLogging { get; set; }
}
