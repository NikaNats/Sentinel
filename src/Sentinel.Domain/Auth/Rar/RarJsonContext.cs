using System.Text.Json.Serialization;

namespace Sentinel.Domain.Auth.Rar;

[JsonSerializable(typeof(AuthorizationDetail[]))]
public partial class RarJsonContext : JsonSerializerContext
{
}
