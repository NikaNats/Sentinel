namespace Sentinel.Persistence.SqlServer;

public sealed class SqlServerPersistenceOptions
{
    public int CommandTimeoutSeconds { get; set; } = 30;

    public int MaxRetryCount { get; set; } = 3;

    public bool EnableSensitiveDataLogging { get; set; }
}
