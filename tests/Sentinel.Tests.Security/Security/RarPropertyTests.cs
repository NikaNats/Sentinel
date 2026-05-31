using System.Linq;
using System.Text.Json;
using FluentAssertions;
using FsCheck;
using FsCheck.FSharp;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sentinel.Domain.Auth.Rar;
using Sentinel.RAR;
using Xunit;

namespace Sentinel.Tests.Security;

public sealed class RarPropertyTests
{
    private readonly RarValidator _validator;

    public RarPropertyTests()
    {
        var options = Options.Create(new RarValidationOptions
        {
            MonetaryPrecisionTolerance = 0.0001m,
            CaseSensitiveComparison = false
        });

        var matcher = new FinancialAuthorizationMatcher(options, NullLogger<FinancialAuthorizationMatcher>.Instance);
        _validator = new RarValidator([matcher], options, NullLogger<RarValidator>.Instance);
    }

    [Fact]
    public void InvariantPayloadMustMatchSignedDetail()
    {
        foreach (var _ in Enumerable.Range(0, 400))
        {
            // FsCheck v3 fix: Use the lowercase ArbMap.defaults static property
            var txnId = Gen.Sample(1, 1, ArbMap.defaults.ArbFor<NonEmptyString>().Generator).Single().Get;
            var amountCents = Gen.Sample(1, 1, ArbMap.defaults.ArbFor<PositiveInt>().Generator).Single();
            var currencyGen = Gen.Sample(1, 1, ArbMap.defaults.ArbFor<NonEmptyString>().Generator).Single();
            var currency = currencyGen.Get.Length >= 3 ? currencyGen.Get[..3].ToUpperInvariant() : "USD";
            var amount = amountCents.Item / 100m;

            var detail = new AuthorizationDetail(
                "urn:sentinel:finance:transfer",
                TransactionId: txnId,
                Amount: amount,
                Currency: currency);

            var payload = JsonSerializer.Serialize(new
            {
                transactionId = txnId,
                amount,
                currency
            });

            var result = _validator.Validate(detail, payload);
            result.IsValid.Should().BeTrue();
        }
    }

    [Fact]
    public void InvariantModifiedAmountMustBeRejected()
    {
        foreach (var _ in Enumerable.Range(0, 400))
        {
            // FsCheck v3 fix: Use the lowercase ArbMap.defaults static property
            var txnId = Gen.Sample(1, 1, ArbMap.defaults.ArbFor<NonEmptyString>().Generator).Single().Get;
            var amountCents = Gen.Sample(1, 1, ArbMap.defaults.ArbFor<PositiveInt>().Generator).Single();
            var currencyGen = Gen.Sample(1, 1, ArbMap.defaults.ArbFor<NonEmptyString>().Generator).Single();
            var deltaCents = Gen.Sample(1, 1, ArbMap.defaults.ArbFor<PositiveInt>().Generator).Single();
            var currency = currencyGen.Get.Length >= 3 ? currencyGen.Get[..3].ToUpperInvariant() : "USD";
            var amount = amountCents.Item / 100m;
            var tamperedAmount = amount + deltaCents.Item / 100m;

            var detail = new AuthorizationDetail(
                "urn:sentinel:finance:transfer",
                TransactionId: txnId,
                Amount: amount,
                Currency: currency);

            var payload = JsonSerializer.Serialize(new
            {
                transactionId = txnId,
                amount = tamperedAmount,
                currency
            });

            var result = _validator.Validate(detail, payload);
            result.IsValid.Should().BeFalse();
        }
    }

    [Fact]
    public void Validate_MalformedPayload_ReturnsFailure()
    {
        var detail = new AuthorizationDetail(
            "urn:sentinel:finance:transfer",
            TransactionId: "txn-1",
            Amount: 10m,
            Currency: "USD");

        var result = _validator.Validate(detail, "{invalid-json");

        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrWhiteSpace();
    }
}
