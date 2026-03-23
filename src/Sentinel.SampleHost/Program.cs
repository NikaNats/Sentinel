using Sentinel.Application.DependencyInjection;
using Sentinel.DependencyInjection;
using Sentinel.Infrastructure;
using Sentinel.Infrastructure.DependencyInjection;

FipsConfiguration.Apply();

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
