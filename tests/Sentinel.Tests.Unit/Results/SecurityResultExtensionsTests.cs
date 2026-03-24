using Sentinel.Security.Abstractions.Results;
using Xunit;
using FluentAssertions;

namespace Sentinel.Tests.Unit.Results;

public sealed class SecurityResultExtensionsTests
{
    [Fact]
    public void Bind_WhenInitialIsSuccess_InvokesBinder()
    {
        var initial = SecurityResultFactory.Create("Step1");

        var result = initial.Bind(val => SecurityResultFactory.Create($"{val} -> Step2"));

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().Be("Step1 -> Step2");
    }

    [Fact]
    public void Bind_WhenInitialIsFailure_ShortCircuitsAndReturnsFailure()
    {
        var initial = SecurityResultFactory.Failure<string>("Initial Error");
        var binderCalled = false;

        var result = initial.Bind(val =>
        {
            binderCalled = true;
            return SecurityResultFactory.Create("Should not reach here");
        });

        binderCalled.Should().BeFalse();
        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Be("Initial Error");
    }

    [Fact]
    public void Map_WhenInitialIsSuccess_TransformsValue()
    {
        var initial = SecurityResultFactory.Create(5);

        var result = initial.Map(val => val * 2);

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().Be(10);
    }

    [Fact]
    public void Match_ExecutesCorrectBranch()
    {
        var successResult = SecurityResultFactory.Create("OK");
        var failureResult = SecurityResultFactory.Failure<string>("FAIL");

        var successMapped = successResult.Match(
            onSuccess: val => $"Success: {val}",
            onFailure: err => $"Error: {err}");

        var failureMapped = failureResult.Match(
            onSuccess: val => $"Success: {val}",
            onFailure: err => $"Error: {err}");

        successMapped.Should().Be("Success: OK");
        failureMapped.Should().Be("Error: FAIL");
    }

    [Fact]
    public void GetValueOrDefault_WhenFailure_ReturnsDefaultFactory()
    {
        var failure = SecurityResultFactory.Failure<int>("Error");

        var val1 = failure.GetValueOrDefault(99);
        var val2 = failure.GetValueOrDefault(err => err.Length); // "Error" length is 5

        val1.Should().Be(99);
        val2.Should().Be(5);
    }
}
