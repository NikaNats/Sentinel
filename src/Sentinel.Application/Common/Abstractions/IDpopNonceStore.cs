// DEPRECATED: Use Sentinel.Security.Abstractions.Nonce.IDpopNonceStore instead.
// This file maintained for backward compatibility during migration to NuGet boundaries.

using Sentinel.Security.Abstractions.Nonce;

namespace Sentinel.Application.Common.Abstractions;

#pragma warning disable CS0618 // Type is obsolete
public interface IDpopNonceStore : Sentinel.Security.Abstractions.Nonce.IDpopNonceStore
{
}
#pragma warning restore CS0618
