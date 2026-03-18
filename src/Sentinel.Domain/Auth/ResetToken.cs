namespace Sentinel.Domain.Auth;

public sealed record ResetToken(string Email, DateTime Expiry, string Nonce)
{
    public string ToPlainString() => $"{Email}|{Expiry.Ticks}|{Nonce}";
}

public interface IResetTokenProvider
{
    string GenerateToken(string email);
    (bool IsValid, string? Email) ValidateToken(string token);
}
