using System.Net;

namespace Sentinel.AspNetCore.Helpers;

/// <summary>
///     High-efficiency helper class for checking IP address ranges.
/// </summary>
internal sealed class IPNetworkMatcher
{
    private readonly List<IPNetwork> _networks = [];

    public IPNetworkMatcher(string[] cidrBlocks)
    {
        ArgumentNullException.ThrowIfNull(cidrBlocks);

        foreach (var cidr in cidrBlocks)
        {
            if (IPNetwork.TryParse(cidr, out var network))
            {
                _networks.Add(network);
            }
            else
            {
                throw new ArgumentException($"Invalid CIDR format: {cidr}", nameof(cidrBlocks));
            }
        }
    }

    /// <summary>
    ///     Checks whether the incoming IP address falls within the trusted network range.
    /// </summary>
    public bool IsTrusted(IPAddress remoteIp)
    {
        var normalizedIp = remoteIp.IsIPv4MappedToIPv6 ? remoteIp.MapToIPv4() : remoteIp;

        for (var i = 0; i < _networks.Count; i++)
        {
            if (_networks[i].Contains(normalizedIp))
            {
                return true;
            }
        }

        return false;
    }
}
