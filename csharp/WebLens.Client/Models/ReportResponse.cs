using System.Text.Json.Serialization;

namespace WebLens.Client.Models;

public record FormData(
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("method")] string Method,
    [property: JsonPropertyName("fields")] List<string> Fields
);

public record CloneInfo(
    [property: JsonPropertyName("fetcher_used")]    string FetcherUsed,
    [property: JsonPropertyName("assets_downloaded")] int AssetsDownloaded,
    [property: JsonPropertyName("assets_failed")]   int AssetsFailed,
    [property: JsonPropertyName("forms_found")]     int FormsFound,
    [property: JsonPropertyName("links_found")]     int LinksFound,
    [property: JsonPropertyName("clone_path")]      string ClonePath,
    [property: JsonPropertyName("page_title")]      string PageTitle
);

public record IntelligenceReport(
    [property: JsonPropertyName("page_type")]     string PageType,
    [property: JsonPropertyName("tech_stack")]    List<string> TechStack,
    [property: JsonPropertyName("summary")]       string Summary,
    [property: JsonPropertyName("forms")]         List<FormData> Forms,
    [property: JsonPropertyName("external_links")] int ExternalLinks,
    [property: JsonPropertyName("internal_links")] int InternalLinks
);

public record PhishRiskReport(
    [property: JsonPropertyName("score")]       int Score,
    [property: JsonPropertyName("verdict")]     string Verdict,
    [property: JsonPropertyName("red_flags")]   List<string> RedFlags,
    [property: JsonPropertyName("explanation")] string Explanation
);

public record WebLensReport(
    [property: JsonPropertyName("job_id")]        string JobId,
    [property: JsonPropertyName("url")]           string Url,
    [property: JsonPropertyName("timestamp")]     string Timestamp,
    [property: JsonPropertyName("status")]        string Status,
    [property: JsonPropertyName("clone")]         CloneInfo CloneInfo,
    [property: JsonPropertyName("intelligence")]  IntelligenceReport Intelligence,
    [property: JsonPropertyName("phishing_risk")] PhishRiskReport PhishingRisk
);

public record JobStatus(
    [property: JsonPropertyName("job_id")]     string JobId,
    [property: JsonPropertyName("url")]        string Url,
    [property: JsonPropertyName("status")]     string Status,
    [property: JsonPropertyName("timestamp")]  string Timestamp,
    [property: JsonPropertyName("risk_score")] int? RiskScore,
    [property: JsonPropertyName("verdict")]    string? Verdict
);

public record CloneResponse(
    [property: JsonPropertyName("job_id")]    string JobId,
    [property: JsonPropertyName("status")]    string Status,
    [property: JsonPropertyName("url")]       string Url,
    [property: JsonPropertyName("timestamp")] string Timestamp
);
