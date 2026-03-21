using System.Net.Http.Headers;
using System.Text;
using Microsoft.Extensions.Options;
using Sentinel.Application.Common.Abstractions;
using Sentinel.Domain.Notifications;

namespace Sentinel.Infrastructure.Notifications;

public sealed class TwilioSmsProvider(
    HttpClient httpClient,
    IOptions<TwilioOptions> options) : INotificationProvider
{
    public string ProviderName => "Twilio";

    public bool CanHandle(NotificationType notificationType)
    {
        return notificationType == NotificationType.Sms
               && options.Value.Enabled
               && !string.IsNullOrWhiteSpace(options.Value.AccountSid)
               && !string.IsNullOrWhiteSpace(options.Value.AuthToken)
               && !string.IsNullOrWhiteSpace(options.Value.FromNumber);
    }

    public async Task SendAsync(NotificationMessage message, string body, CancellationToken ct)
    {
        var requestUri =
            $"https://api.twilio.com/2010-04-01/Accounts/{Uri.EscapeDataString(options.Value.AccountSid)}/Messages.json";
        using var request = new HttpRequestMessage(HttpMethod.Post, requestUri)
        {
            Content = new FormUrlEncodedContent(
            [
                new KeyValuePair<string, string>("To", message.To.Identifier),
                new KeyValuePair<string, string>("From", options.Value.FromNumber),
                new KeyValuePair<string, string>("Body", body)
            ])
        };

        var credentials =
            Convert.ToBase64String(Encoding.ASCII.GetBytes(options.Value.AccountSid + ":" + options.Value.AuthToken));
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        using var response = await httpClient.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
    }
}
