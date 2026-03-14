using Sentinel.Application.DependencyInjection;
using Sentinel.DependencyInjection;
using Sentinel.Infrastructure.DependencyInjection;

AppContext.SetSwitch("Switch.System.Security.Cryptography.UseLegacyFipsThrow", false);

if (OperatingSystem.IsLinux()
    && File.Exists("/proc/sys/crypto/fips_enabled")
    && File.ReadAllText("/proc/sys/crypto/fips_enabled").Trim() == "1")
{
    Console.WriteLine("Sentinel API is running in FIPS-enabled mode.");
}

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.AddApiWebHostDefaults();

builder.Services
    .AddApiLayer()
    .AddApplicationLayer()
    .AddInfrastructureLayer(builder.Configuration);

var app = builder.Build();

app.UseApiLayer();

app.Run();

public partial class Program;
