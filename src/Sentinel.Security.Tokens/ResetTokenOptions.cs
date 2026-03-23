namespace Sentinel.Security.Tokens;

public sealed class ResetTokenOptions
{
    public string TokenSigningKey { get; set; } = string.Empty;
    public int LifetimeMinutes { get; set; } = 15;
}
