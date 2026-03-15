// Sentinel Security API - FAPI 2.0 Compliant
namespace Sentinel.Infrastructure.Auth;

internal static class KeycloakAuthorityEndpoints
{
    public static bool TryBuild(string authority, out Uri tokenEndpoint, out Uri adminRealmEndpoint)
    {
        tokenEndpoint = default!;
        adminRealmEndpoint = default!;

        if (!Uri.TryCreate(authority, UriKind.Absolute, out var authorityUri))
        {
            return false;
        }

        var segments = authorityUri.AbsolutePath
            .Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var realmMarkerIndex = Array.FindIndex(
            segments,
            static segment => string.Equals(segment, "realms", StringComparison.OrdinalIgnoreCase));

        if (realmMarkerIndex < 0 || realmMarkerIndex + 1 >= segments.Length)
        {
            return false;
        }

        var realmName = segments[realmMarkerIndex + 1];
        var prefixSegments = segments[..realmMarkerIndex];
        var prefix = prefixSegments.Length == 0
            ? string.Empty
            : "/" + string.Join('/', prefixSegments);

        var authorityRoot = authorityUri.GetLeftPart(UriPartial.Authority);

        tokenEndpoint = new Uri($"{authorityRoot}{prefix}/realms/{Uri.EscapeDataString(realmName)}/protocol/openid-connect/token", UriKind.Absolute);
        adminRealmEndpoint = new Uri($"{authorityRoot}{prefix}/admin/realms/{Uri.EscapeDataString(realmName)}/", UriKind.Absolute);
        return true;
    }
}
