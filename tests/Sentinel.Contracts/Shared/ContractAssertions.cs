using System.Reflection;

namespace Sentinel.Contracts.Shared;

/// <summary>
///     Shared contract assertions: fail loudly, name the violating pin.
/// </summary>
public static class ContractAssertions
{
    /// <summary>
    ///     Asserts that a contract suite type carries the expected [ContractVersion] pin,
    ///     proving the suite is versioned and CI-executable (never skippable).
    /// </summary>
    public static void AssertPinned(Type suiteType, string contractId, string version)
    {
        var attribute = suiteType.GetCustomAttribute<ContractVersionAttribute>();
        attribute.Should().NotBeNull($"contract suite '{suiteType.Name}' MUST declare [ContractVersionAttribute]");
        attribute!.ContractId.Should().Be(contractId, "suite must pin the CONTRACT-001 spec");
        attribute.Version.Should().Be(version, "suite must pin its exact contract version");
    }
}