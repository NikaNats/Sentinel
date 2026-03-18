namespace Sentinel.Application.Auth.Models;

public enum FederationSyncMode
{
    Legacy = 0,
    Import = 1,
    Force = 2
}

public sealed class GoogleFederationOptions
{
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public FederationSyncMode SyncMode { get; set; } = FederationSyncMode.Import;
    public bool Enabled { get; set; }
    public bool TrustEmail { get; set; } = true;
    public bool StoreToken { get; set; } = true;
}

public sealed class GitHubFederationOptions
{
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public FederationSyncMode SyncMode { get; set; } = FederationSyncMode.Import;
    public bool Enabled { get; set; }
    public bool TrustEmail { get; set; } = true;
    public bool StoreToken { get; set; } = true;
}

public sealed class SocialFederationOptions
{
    public GoogleFederationOptions Google { get; set; } = new();
    public GitHubFederationOptions GitHub { get; set; } = new();
    public string FirstBrokerLoginFlowAlias { get; set; } = "first broker login";
}
