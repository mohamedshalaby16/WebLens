using System.Text.Json.Serialization;

namespace WebLens.Client.Models;

public record CloneRequest(
    [property: JsonPropertyName("url")] string Url,
    [property: JsonPropertyName("force_fetcher")] string? ForceFetcher = null
);
