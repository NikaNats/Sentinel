using System;

namespace Sentinel.Security.Diagnostics;

/// <summary>
/// Manages the state and retrieval of the privacy master pepper.
/// </summary>
public interface IPrivacyKeyManager
{
    /// <summary>
    /// Gets the current active master pepper.
    /// </summary>
    ReadOnlySpan<byte> GetMasterPepper();
}
