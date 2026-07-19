using System.Text;
using System.Text.Json;
using FsCheck;
using FsCheck.Fluent;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Domain.Auth.Rar;
using Sentinel.DPoP;
using Sentinel.RAR;

namespace Sentinel.Tests.Security.Security;

public sealed class DpopAndRarPropertyTests
{
    private readonly RarValidator _rarValidator;
    private readonly DpopThumbprintComputer _thumbprintComputer = new();

    public DpopAndRarPropertyTests()
    {
        var options = Options.Create(new RarValidationOptions
        {
            MonetaryPrecisionTolerance = 0.0001m,
            CaseSensitiveComparison = false
        });

        var matcher = new FinancialAuthorizationMatcher(options, NullLogger<FinancialAuthorizationMatcher>.Instance);
        _rarValidator = new RarValidator(new[] { matcher }, options, NullLogger<RarValidator>.Instance);
    }

    [Fact(DisplayName = "🧪 FsCheck: DPoP thumbprints must be stable, valid Base64Url, and exactly 43 characters")]
    public void Verify_DpopThumbprints_AreStableAndValidBase64Url()
    {
        var property = Prop.ForAll<string>(coordinate =>
        {
            if (string.IsNullOrWhiteSpace(coordinate) || coordinate.Length <= 10)
            {
                return true;
            }

            var jwk = new Dictionary<string, string>
            {
                ["kty"] = "EC",
                ["crv"] = "P-256",
                ["x"] = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(coordinate)),
                ["y"] = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(coordinate))
            };

            using var doc =
                JsonDocument.Parse(JsonSerializer.Serialize(jwk, DpopJsonContext.Default.DictionaryStringString));
            var thumbprint = _thumbprintComputer.Compute(doc.RootElement);

            var isValid = !string.IsNullOrWhiteSpace(thumbprint)
                          && thumbprint.Length == 43
                          && thumbprint.All(c => char.IsLetterOrDigit(c) || c == '-' || c == '_');

            return isValid;
        });

        Check.QuickThrowOnFailure(property);
    }

    [Fact(DisplayName = "🧪 FsCheck: Any financial transfer exceeding authorized limits must always be rejected")]
    public void Verify_RarValidation_RejectsAmountsExceedingAuthorizedLimits()
    {
        var property = Prop.ForAll<double, double>((authAmountDouble, deltaDouble) =>
        {
            if (double.IsNaN(authAmountDouble) || double.IsInfinity(authAmountDouble) ||
                double.IsNaN(deltaDouble) || double.IsInfinity(deltaDouble))
            {
                return true;
            }

            if (Math.Abs(authAmountDouble) > 1_000_000_000.0 || Math.Abs(deltaDouble) > 1_000_000_000.0)
            {
                return true;
            }

            var authAmount = (decimal)Math.Abs(authAmountDouble);
            var delta = (decimal)Math.Abs(deltaDouble);

            if (authAmount < 0.01m || delta < 0.01m)
            {
                return true;
            }

            var exceededAmount = authAmount + delta;

            var detail = new AuthorizationDetail(
                "urn:sentinel:finance:transfer",
                TransactionId: "txn-property-test",
                Amount: authAmount,
                Currency: "USD");

            var payload = JsonSerializer.Serialize(new
            {
                transactionId = "txn-property-test",
                amount = exceededAmount,
                currency = "USD"
            });

            var result = _rarValidator.Validate(detail, payload);
            return !result.IsValid;
        });

        Check.QuickThrowOnFailure(property);
    }
}
