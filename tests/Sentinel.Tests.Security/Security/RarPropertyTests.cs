using System.Text.Json;
using FluentAssertions;
using FsCheck;
using FsCheck.Xunit;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sentinel.Domain.Auth.Rar;
using Sentinel.RAR;

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

    [Property(MaxTest = 400)]
    public bool InvariantPayloadMustMatchSignedDetail(
        NonEmptyString txnIdGen,
        PositiveInt amountCents,
        NonEmptyString currencyGen)
    {
        var txnId = txnIdGen.Get;
        var currency = currencyGen.Get.Length >= 3 ? currencyGen.Get[..3].ToUpperInvariant() : "USD";
        var amount = amountCents.Item / 100m;

        var detail = new AuthorizationDetail(
            Type: "urn:sentinel:finance:transfer",
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
        return result.IsValid;
    }

    [Property(MaxTest = 400)]
    public bool InvariantModifiedAmountMustBeRejected(
        NonEmptyString txnIdGen,
        PositiveInt amountCents,
        NonEmptyString currencyGen,
        PositiveInt deltaCents)
    {
        var txnId = txnIdGen.Get;
        var currency = currencyGen.Get.Length >= 3 ? currencyGen.Get[..3].ToUpperInvariant() : "USD";
        var amount = amountCents.Item / 100m;
        var tamperedAmount = amount + (deltaCents.Item / 100m);

        var detail = new AuthorizationDetail(
            Type: "urn:sentinel:finance:transfer",
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
        return !result.IsValid;
    }

    [Fact]
    public void Validate_MalformedPayload_ReturnsFailure()
    {
        var detail = new AuthorizationDetail(
            Type: "urn:sentinel:finance:transfer",
            TransactionId: "txn-1",
            Amount: 10m,
            Currency: "USD");

        var result = _validator.Validate(detail, "{invalid-json");

        result.IsValid.Should().BeFalse();
        result.Error.Should().NotBeNullOrWhiteSpace();
    }
}
