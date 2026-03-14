using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Testcontainers.Redis;
using Xunit;

namespace Sentinel.Tests.Integration.Fixtures;

public sealed class SentinelApiFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    private readonly RedisContainer redisContainer;
    private string redisConnectionString = "localhost:6379";

    public SentinelApiFactory()
    {
        redisContainer = new RedisBuilder("redis:7.4-alpine").Build();
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Keycloak:Authority"] = "https://localhost:8443/realms/sentinel",
                ["Keycloak:Audience"] = "sentinel-api",
                ["Keycloak:RequireHttpsMetadata"] = "false",
                ["ConnectionStrings:Redis"] = redisConnectionString,
                ["FeatureFlags:Auth:DpopFlow"] = "true"
            });
        });

        builder.ConfigureTestServices(services =>
        {
            services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                options.TokenValidationParameters.IssuerSigningKey = TestTokenIssuer.AuthoritySecurityKey;
                options.TokenValidationParameters.ValidateIssuerSigningKey = true;
                options.TokenValidationParameters.ValidIssuer = "https://localhost:8443/realms/sentinel";
                options.TokenValidationParameters.ValidAudience = "sentinel-api";
                options.RequireHttpsMetadata = false;
                options.ConfigurationManager = null;
            });
        });
    }

    public async Task InitializeAsync()
    {
        await redisContainer.StartAsync();
        redisConnectionString = redisContainer.GetConnectionString();
        _ = CreateClient();
    }

    async Task IAsyncLifetime.DisposeAsync()
    {
        await redisContainer.DisposeAsync();
        await base.DisposeAsync();
    }
}
