namespace Sentinel.Infrastructure.Auth.Ssf;

public sealed class SsfOptions
{
    public const string SectionName = "Ssf";

    public bool Enabled { get; init; }

    public bool RequireAuthToken { get; init; } = true;

    public string? AuthToken { get; init; }

    public int SessionRevocationTtlSeconds { get; init; } = 28_800;

    public int MaxEventAgeSeconds { get; init; } = 300;

    public int AllowedClockSkewSeconds { get; init; } = 300;
}
