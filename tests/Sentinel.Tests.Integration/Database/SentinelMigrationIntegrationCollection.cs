using Sentinel.Tests.Integration.Database.Fixtures;
using Xunit;

namespace Sentinel.Tests.Integration.Database;

/// <summary>
/// Collection fixture for migration tests that require the full Sentinel stack
/// </summary>
[CollectionDefinition("Sentinel Migration Integration")]
public sealed class SentinelMigrationIntegrationCollection : ICollectionFixture<MigrationTestFixture>
{
}