namespace Sentinel.Application.Common.Abstractions;

public interface ITemplateRenderer
{
    Task<string> RenderAsync(string templateName, object data, CancellationToken ct);
}
