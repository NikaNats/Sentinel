// Sentinel Security API - FAPI 2.0 Compliant
// This file exists solely to support test infrastructure and WebApplicationFactory
// It is not used in production scenarios

namespace Sentinel.AspNetCore;

/// <summary>
/// Minimal program class required for WebApplicationFactory integration tests.
/// ✅ FIX: Provides an entry point to satisfy the .NET Host Builder requirements.
/// </summary>
public static partial class Program
{
    /// <summary>
    /// Entry point for the application. Required by .NET runtime for WebApplicationFactory.
    /// The actual application configuration is provided via dependency injection in a partial class or extension.
    /// </summary>
    public static void Main() { }
}
