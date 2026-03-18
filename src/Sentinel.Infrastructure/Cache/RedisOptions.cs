namespace Sentinel.Infrastructure.Cache;

public sealed class RedisOptions
{
    public string[] EndPoints { get; set; } = [];
    public string UserName { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public bool UseSsl { get; set; } = true;
    public string ServiceName { get; set; } = string.Empty;
    public bool AllowAdmin { get; set; }
    public int ConnectTimeout { get; set; } = 5000;
    public bool EnableInMemFallback { get; set; } = true;
}
