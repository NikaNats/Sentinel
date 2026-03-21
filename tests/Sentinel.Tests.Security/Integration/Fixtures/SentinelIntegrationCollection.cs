using Xunit;

namespace Sentinel.Tests.Integration.Fixtures;

[CollectionDefinition("Sentinel Integration")]
public sealed class SentinelIntegrationCollection : ICollectionFixture<SentinelApiFactory>
{
}
