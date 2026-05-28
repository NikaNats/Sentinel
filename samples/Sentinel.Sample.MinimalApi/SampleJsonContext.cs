using System.Text.Json.Serialization;
using Sentinel.Sample.MinimalApi.Endpoints;

namespace Sentinel.Sample.MinimalApi;

/// <summary>
/// JSON serialization context for the Sample application local DTOs.
/// </summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(CreateDocumentRequest))]
[JsonSerializable(typeof(DocumentSummaryDto))]
[JsonSerializable(typeof(DocumentDetailDto))]
[JsonSerializable(typeof(TransferRequest))]
[JsonSerializable(typeof(TransferResponse))]
[JsonSerializable(typeof(SecurityContextDto))]
[JsonSerializable(typeof(SampleInfoResponse))]
[JsonSerializable(typeof(EndpointMap))]
[JsonSerializable(typeof(HealthResponse))]
[JsonSerializable(typeof(Microsoft.AspNetCore.Mvc.ProblemDetails))]
[JsonSerializable(typeof(Microsoft.AspNetCore.Mvc.ValidationProblemDetails))]
[JsonSerializable(typeof(System.Collections.Generic.IEnumerable<DocumentSummaryDto>))]
[JsonSerializable(typeof(System.Collections.Generic.List<DocumentSummaryDto>))]
internal sealed partial class SampleJsonContext : JsonSerializerContext
{
}
