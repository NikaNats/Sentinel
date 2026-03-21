namespace Sentinel.Infrastructure.Auth.SdJwt;

public sealed class SdJwtOptions
{
    public const string SectionName = "SdJwt";

    public bool Enabled { get; init; }

    public string AuthenticationScheme { get; init; } = "SdJwt";

    public int KeyBindingMaxAgeSeconds { get; init; } = 60;

    public bool RequireKeyBindingNonce { get; init; }
}
