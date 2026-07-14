using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Sentinel.AspNetCore.Extensions;
using Sentinel.Security.Abstractions.Options;

namespace Sentinel.Tests.Unit.Unit;

public sealed class DpopStartupValidationTests
{
    [Fact(DisplayName = "⏱️ Startup: Invalid DPoP algorithm config MUST block application bootstrap")]
    public void AddDPoPValidation_WithInvalidConfig_ThrowsOptionsValidationExceptionOnStart()
    {
        var services = new ServiceCollection();

        var inMemoryConfig = new Dictionary<string, string?>
        {
            ["DPoP:AllowedAlgorithms:0"] = "RS256",
            ["DPoP:AllowedAlgorithms:1"] = "ES256"
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(inMemoryConfig)
            .Build();

        services.AddSingleton<IConfiguration>(configuration);
        services.AddLogging();

        services.AddSentinelAspNetCore().AddDPoPValidation();

        var act = () =>
        {
            using var provider = services.BuildServiceProvider();
            _ = provider.GetRequiredService<IOptions<DPoPOptions>>().Value;
        };

        act.Should().Throw<OptionsValidationException>()
            .WithMessage("*CRITICAL SECURITY INVARIANT VIOLATED*");
    }
}
