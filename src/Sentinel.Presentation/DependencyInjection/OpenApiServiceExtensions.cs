using Microsoft.OpenApi;

namespace Sentinel.DependencyInjection;

internal static class OpenApiServiceExtensions
{
    public static IServiceCollection AddSentinelOpenApi(this IServiceCollection services) =>
        services.AddOpenApi(options =>
            options.AddDocumentTransformer((doc, _, _) =>
            {
                doc.Info.Version = "1.0.0";
                doc.Info.Title = "Sentinel API";
                doc.Info.Description =
                    "FAPI 2.0 compliant security API with DPoP, ACR step-up, idempotency and replay protection";
                doc.Info.Contact = new OpenApiContact
                {
                    Name = "Nika Nats",
                    Email = "nika.nacvlishvili1@gmail.com"
                };
                return Task.CompletedTask;
            }));
}
