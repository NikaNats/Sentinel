namespace Sentinel.Application.Auth.Options;

public sealed record PasswordPolicyOptions
{
    public const string SectionName = "Sentinel:Security:PasswordPolicy";

    public int MinimumLength { get; set; } = 12;
    public int MaximumLength { get; set; } = 128;
    public bool RequireUppercase { get; set; } = true;
    public bool RequireLowercase { get; set; } = true;
    public bool RequireDigit { get; set; } = true;
    public bool RequireNonAlphanumeric { get; set; } = true;
    public double MinimumEntropyBits { get; set; } = 60.0;
    public string[] CustomBlacklist { get; set; } = [];
}
