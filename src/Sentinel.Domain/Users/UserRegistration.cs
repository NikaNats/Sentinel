namespace Sentinel.Domain.Users;

public sealed class UserRegistration
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public string Email { get; init; } = string.Empty;
    public string Username { get; init; } = string.Empty;
    public ConsentInfo Consent { get; init; } = default!;
}
