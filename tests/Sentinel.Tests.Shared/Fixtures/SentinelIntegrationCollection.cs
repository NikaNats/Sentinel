namespace Sentinel.Tests.Shared.Fixtures;

using Xunit;

[CollectionDefinition("Sentinel Integration")]
public sealed class SentinelIntegrationCollection : ICollectionFixture<SentinelApiFactory>
{
}
