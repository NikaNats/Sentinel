using System.Text.Json.Serialization;

namespace Sentinel.Security.Captcha;

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(TurnstileVerifyResponse))]
public sealed partial class CaptchaJsonContext : JsonSerializerContext
{
}

public sealed record TurnstileVerifyResponse(bool Success);
