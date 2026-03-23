using System.ComponentModel.DataAnnotations;

namespace Sentinel.SampleHost.Models;

public sealed record UpdateDocumentRequest(
    [Required] [MaxLength(128)] string Title,
    [Required] [MaxLength(4096)] string Content);
