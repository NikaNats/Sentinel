using Fluid;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Sentinel.Application.Common.Abstractions;

namespace Sentinel.Infrastructure.Notifications;

public sealed class FluidTemplateRenderer(
    IHostEnvironment hostEnvironment,
    IOptions<NotificationOptions> options) : ITemplateRenderer
{
    private readonly FluidParser parser = new();

    public async Task<string> RenderAsync(string templateName, object data, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(templateName))
        {
            throw new ArgumentException("Template name is required.", nameof(templateName));
        }

        var templatesRoot = options.Value.TemplateRootPath;
        var templatePath = Path.Combine(
            hostEnvironment.ContentRootPath,
            templatesRoot,
            templateName + ".liquid");

        var source = await File.ReadAllTextAsync(templatePath, ct);
        if (!parser.TryParse(source, out var template, out var error))
        {
            throw new InvalidOperationException("Template parse failure: " + error);
        }

        var context = new TemplateContext(data);
        return await template.RenderAsync(context);
    }
}
