using Microsoft.AspNetCore.Authorization;

namespace Sentinel.Application.Auth.Models;

public sealed class AcrRequirement(string minimumAcr) : IAuthorizationRequirement
{
    public string MinimumAcr { get; } = minimumAcr;
}
