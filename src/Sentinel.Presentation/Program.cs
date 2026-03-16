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
    .AddInfrastructureLayer(builder.Configuration)
    .AddSentinelOpenApi();

var app = builder.Build();

app.UseApiLayer();

if (app.Environment.IsDevelopment())
    app.MapDeveloperDocs();

app.Run();

public partial class Program;
