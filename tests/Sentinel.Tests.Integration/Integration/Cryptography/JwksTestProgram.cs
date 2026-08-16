// Test infrastructure - suppress CA warnings that are not relevant for test code
#pragma warning disable CA2000 // Dispose objects before losing scope

using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Sentinel.Security.Diagnostics;
using Sentinel.Tests.Shared;
using Xunit;
using FluentAssertions;

namespace Sentinel.Tests.Integration.Cryptography;

/// <summary>
///     Minimal program for JWKS rotation tests - only JWT Bearer auth, no extra validation.
/// </summary>
internal sealed class JwksTestProgram
{
    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.ConfigureServices(services =>
                {
                    services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                        .AddJwtBearer(options =>
                        {
                            options.MapInboundClaims = false;
                            options.RequireHttpsMetadata = false;
                        });

                    services.AddAuthorizationBuilder()
                        .AddPolicy("Protected", p => p.RequireAuthenticatedUser());

                    services.AddRouting();
                })
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/protected", () => "OK").RequireAuthorization("Protected");
                        endpoints.MapGet("/healthz", () => "OK").AllowAnonymous();
                    });
                });
            })
            .ConfigureAppConfiguration((_, config) =>
            {
                // Configuration is provided by the test factory
            });
}