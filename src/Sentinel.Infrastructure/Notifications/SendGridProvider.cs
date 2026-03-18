using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Extensions.Options;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Domain.Notifications;

namespace Sentinel.Infrastructure.Notifications;

public sealed class SendGridProvider(
    HttpClient httpClient,
    IOptions<SendGridOptions> options) : INotificationProvider
{
    public string ProviderName => "SendGrid";

    public bool CanHandle(NotificationType notificationType)
    {
        return notificationType == NotificationType.Email
            && options.Value.Enabled
            && !string.IsNullOrWhiteSpace(options.Value.ApiKey)
            && !string.IsNullOrWhiteSpace(options.Value.FromEmail);
    }

    public async Task SendAsync(NotificationMessage message, string body, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.sendgrid.com/v3/mail/send");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", options.Value.ApiKey);
        request.Content = JsonContent.Create(new
        {
            personalizations = new[]
            {
                new
                {
                    to = new[] { new { email = message.To.Identifier, name = message.To.Name } },
                    subject = message.Subject
                }
            },
            from = new { email = options.Value.FromEmail },
            content = new[]
            {
                new { type = "text/html", value = body }
            }
        });

        using var response = await httpClient.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
    }
}
