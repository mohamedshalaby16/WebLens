using System.Net.Http.Json;
using System.Text.Json;
using WebLens.Client.Models;

namespace WebLens.Client;

public class ApiClient : IDisposable
{
    private readonly HttpClient _http;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public ApiClient(string baseUrl = "http://localhost:8000")
    {
        _http = new HttpClient { BaseAddress = new Uri(baseUrl) };
    }

    public async Task<CloneResponse> PostCloneAsync(string url, string? forceFetcher = null)
    {
        var request = new CloneRequest(url, forceFetcher);
        var response = await _http.PostAsJsonAsync("/clone", request, JsonOptions);
        response.EnsureSuccessStatusCode();

        var result = await response.Content.ReadFromJsonAsync<CloneResponse>(JsonOptions)
            ?? throw new InvalidOperationException("Empty response from /clone");
        return result;
    }

    public async Task<WebLensReport> GetReportAsync(string jobId)
    {
        var response = await _http.GetAsync($"/report/{jobId}");
        response.EnsureSuccessStatusCode();

        var report = await response.Content.ReadFromJsonAsync<WebLensReport>(JsonOptions)
            ?? throw new InvalidOperationException($"Empty response for report {jobId}");
        return report;
    }

    public async Task<List<JobStatus>> GetJobsAsync()
    {
        var response = await _http.GetAsync("/jobs");
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<List<JobStatus>>(JsonOptions)
            ?? [];
    }

    public async Task<bool> HealthCheckAsync()
    {
        try
        {
            var response = await _http.GetAsync("/health");
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    public void Dispose() => _http.Dispose();
}
