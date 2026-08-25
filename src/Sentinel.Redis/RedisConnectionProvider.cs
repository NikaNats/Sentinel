namespace Sentinel.Redis;

internal sealed class RedisConnectionProvider : IRedisConnectionProvider
{
    private readonly SemaphoreSlim _connectionLock = new(1, 1);
    private readonly ILogger<RedisConnectionProvider> _logger;
    private readonly ConfigurationOptions _options;
    private bool _disposed;
    private ConnectionMultiplexer? _multiplexer;

    public RedisConnectionProvider(RedisOptions redisOptions, ILogger<RedisConnectionProvider> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        ArgumentNullException.ThrowIfNull(redisOptions);

        _options = ConfigurationOptions.Parse(redisOptions.EndPoint ?? "localhost:6379");

        _options.Ssl = redisOptions.UseSsl;
        _options.Password = redisOptions.Password;

        // Sentinel High Availability Configuration
        if (!string.IsNullOrWhiteSpace(redisOptions.ServiceName))
        {
            _options.ServiceName = redisOptions.ServiceName;
            _logger.LogInformation("Redis HA Sentinel mode enabled for Master Service: '{ServiceName}'", redisOptions.ServiceName);
        }

        _options.AbortOnConnectFail = false;
        _options.ConnectRetry = 5;
        _options.KeepAlive = 30;

        _options.ConnectTimeout = redisOptions.ConnectTimeout > 0 ? redisOptions.ConnectTimeout : 5000;
        _options.SyncTimeout = redisOptions.SyncTimeout > 0 ? redisOptions.SyncTimeout : 3000;
        _options.AsyncTimeout = redisOptions.SyncTimeout > 0 ? redisOptions.SyncTimeout : 3000;

        // Security Guard: Block dangerous administrative commands from application layer
        _options.CommandMap = CommandMap.Create(new Dictionary<string, string?>
        {
            ["KEYS"] = null,
            ["FLUSHALL"] = null,
            ["FLUSHDB"] = null,
            ["SHUTDOWN"] = null,
            ["CONFIG"] = null
        });

        _options.ClientName = "Sentinel_Security_Gateway_Node";
        _options.ChannelPrefix = RedisChannel.Literal("sentinel");
    }

    public async ValueTask<IConnectionMultiplexer> GetConnectionAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_multiplexer is { IsConnected: true })
        {
            return _multiplexer;
        }

        await _connectionLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_multiplexer is { IsConnected: true })
            {
                return _multiplexer;
            }

            _logger.LogInformation("Establishing resilient connection to Redis cluster/sentinel pool...");

            _multiplexer = await ConnectionMultiplexer.ConnectAsync(_options).ConfigureAwait(false);

            _multiplexer.ConnectionRestored += (_, args) =>
                _logger.LogInformation("Redis connection restored. Active Endpoint: {Endpoint}, FailureType: {Type}", args.EndPoint, args.FailureType);

            _multiplexer.ConnectionFailed += (_, args) =>
                _logger.LogWarning(args.Exception, "Redis connection failed on Endpoint: {Endpoint}, FailureType: {Type}", args.EndPoint, args.FailureType);

            _multiplexer.ErrorMessage += (_, args) =>
                _logger.LogError("Redis server emitted error on {Endpoint}: {Message}", args.EndPoint, args.Message);

            return _multiplexer;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Failed to connect to Redis endpoints: '{EndPoints}'", string.Join(", ", _options.EndPoints));
            throw;
        }
        finally
        {
            _connectionLock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        await _connectionLock.WaitAsync().ConfigureAwait(false);
        try
        {
            _disposed = true;
            if (_multiplexer != null)
            {
                await _multiplexer.DisposeAsync().ConfigureAwait(false);
            }
        }
        finally
        {
            _connectionLock.Release();
            _connectionLock.Dispose();
        }
    }
}