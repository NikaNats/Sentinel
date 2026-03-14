using Xunit;

namespace Sentinel.Tests.Integration.Fixtures;

[CollectionDefinition("Sentinel Real Keycloak Integration")]
public sealed class SentinelRealKeycloakIntegrationCollection : ICollectionFixture<RealKeycloakApiFactory>
{
}
