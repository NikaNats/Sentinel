using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Domain.Auth;

namespace Sentinel.Infrastructure.Auth;

public sealed class HmacResetTokenProvider(IOptions<ResetTokenOptions> options) : IResetTokenProvider
{
    private readonly byte[] signingKey = ResolveSigningKey(options.Value.TokenSigningKey);
    private readonly int lifetimeMinutes = options.Value.LifetimeMinutes <= 0 ? 15 : options.Value.LifetimeMinutes;

    public string GenerateToken(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            throw new ArgumentException("Email is required.", nameof(email));
        }

        var resetToken = new ResetToken(
            email.Trim(),
            DateTime.UtcNow.AddMinutes(lifetimeMinutes),
            Guid.NewGuid().ToString("N"));

        var payload = resetToken.ToPlainString();
        var payloadBytes = Encoding.UTF8.GetBytes(payload);

        using var hmac = new HMACSHA256(signingKey);
        var signature = hmac.ComputeHash(payloadBytes);

        return $"{Base64UrlEncoder.Encode(payloadBytes)}.{Base64UrlEncoder.Encode(signature)}";
    }

    public (bool IsValid, string? Email) ValidateToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return (false, null);
        }

        var parts = token.Split('.', StringSplitOptions.TrimEntries);
        if (parts.Length != 2)
        {
            return (false, null);
        }

        byte[] payloadBytes;
        byte[] receivedSignature;
        try
        {
            payloadBytes = Base64UrlEncoder.DecodeBytes(parts[0]);
            receivedSignature = Base64UrlEncoder.DecodeBytes(parts[1]);
        }
        catch (FormatException)
        {
            return (false, null);
        }

        using var hmac = new HMACSHA256(signingKey);
        var expectedSignature = hmac.ComputeHash(payloadBytes);

        if (receivedSignature.Length != expectedSignature.Length
            || !CryptographicOperations.FixedTimeEquals(receivedSignature, expectedSignature))
        {
            return (false, null);
        }

        var payload = Encoding.UTF8.GetString(payloadBytes);
        var values = payload.Split('|', StringSplitOptions.None);
        if (values.Length != 3)
        {
            return (false, null);
        }

        var email = values[0];
        if (!long.TryParse(values[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var expiryTicks))
        {
            return (false, null);
        }

        DateTime expiry;
        try
        {
            expiry = new DateTime(expiryTicks, DateTimeKind.Utc);
        }
        catch (ArgumentOutOfRangeException)
        {
            return (false, null);
        }

        if (expiry <= DateTime.UtcNow)
        {
            return (false, null);
        }

        return (true, email);
    }

    private static byte[] ResolveSigningKey(string signingKey)
    {
        if (string.IsNullOrWhiteSpace(signingKey))
        {
            throw new InvalidOperationException("Password reset token signing key is not configured.");
        }

        try
        {
            return Convert.FromBase64String(signingKey);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException("Password reset token signing key must be Base64 encoded.", ex);
        }
    }
}
