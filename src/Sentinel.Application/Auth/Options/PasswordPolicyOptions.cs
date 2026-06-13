namespace Sentinel.Application.Auth.Options;

public sealed record PasswordPolicyOptions
{
    public const string SectionName = "Sentinel:Security:PasswordPolicy";

    public int MinimumLength { get; init; } = 12;
    public int MaximumLength { get; init; } = 128;
    public bool RequireUppercase { get; init; } = true;
    public bool RequireLowercase { get; init; } = true;
    public bool RequireDigit { get; init; } = true;
    public bool RequireNonAlphanumeric { get; init; } = true;
    public double MinimumEntropyBits { get; init; } = 60.0;
    public string[] CustomBlacklist { get; init; } = [];
}
