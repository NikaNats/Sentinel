namespace Sentinel.Tests.Shared.Fixtures;

using Xunit;

[CollectionDefinition("Sentinel Real Keycloak Integration")]
public sealed class SentinelRealKeycloakIntegrationCollection : ICollectionFixture<RealKeycloakApiFactory>
{
}
