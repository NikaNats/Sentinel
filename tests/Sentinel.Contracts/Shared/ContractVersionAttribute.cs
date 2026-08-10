namespace Sentinel.Contracts.Shared;

/// <summary>
///     Marks a contract test surface with its pinned contract version.
///     The CI contract gate uses this to prove every CONTRACT-001 surface
///     was executed (no accidental skips).
/// </summary>
[AttributeUsage(AttributeTargets.Class)]
public sealed class ContractVersionAttribute(string contractId, string version) : Attribute
{
    /// <summary>Spec identifier, e.g. "CONTRACT-001".</summary>
    public string ContractId { get; } = contractId;

    /// <summary>Pinned contract version, e.g. "1.0".</summary>
    public string Version { get; } = version;

    /// <summary>Dependency surface pinned by this suite (e.g. "Keycloak 26.6.4").</summary>
    public string? Target { get; set; }
}