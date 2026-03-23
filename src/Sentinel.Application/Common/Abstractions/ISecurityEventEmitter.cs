// DEPRECATED: Use Sentinel.Security.Abstractions.Security.ISecurityEventEmitter instead.
// This file maintained for backward compatibility during migration to NuGet boundaries.

using Sentinel.Security.Abstractions.Security;

namespace Sentinel.Application.Common.Abstractions;

#pragma warning disable CS0618 // Type is obsolete
public interface ISecurityEventEmitter : Sentinel.Security.Abstractions.Security.ISecurityEventEmitter
{
    /// <summary>
    /// Emits an event when an authentication failure occurs (legacy method - use EmitDpopValidationFailure).
    /// </summary>
    void EmitAuthFailure(string reason, string? sub, string ipHash);
}
#pragma warning restore CS0618
