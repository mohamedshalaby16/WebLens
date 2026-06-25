using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using WebLens.Desktop.Models;

namespace WebLens.Desktop.Services
{
    public class ApiClient
    {
        private readonly HttpClient _http;
        private readonly string _base;
        private readonly JsonSerializerSettings _jsonSettings;

        public ApiClient(string baseUrl = "http://localhost:8000")
        {
            _base = baseUrl;
            _http = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(120)
            };
            _jsonSettings = new JsonSerializerSettings
            {
                ContractResolver = new DefaultContractResolver
                {
                    NamingStrategy = new SnakeCaseNamingStrategy()
                }
            };
        }

        public async Task<CloneResponse> CloneAsync(string url)
        {
            var payload = JsonConvert.SerializeObject(new { url });
            var content = new StringContent(payload, Encoding.UTF8, "application/json");
            var response = await _http.PostAsync($"{_base}/clone", content);
            var json = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
                throw new Exception($"API error {response.StatusCode}: {json}");

            return JsonConvert.DeserializeObject<CloneResponse>(json, _jsonSettings)!;
        }

        public async Task<WebLensReport> GetReportAsync(string jobId)
        {
            var response = await _http.GetAsync($"{_base}/report/{jobId}");
            var json = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
                throw new Exception($"API error {response.StatusCode}: {json}");

            return JsonConvert.DeserializeObject<WebLensReport>(json, _jsonSettings)!;
        }

        public async Task<byte[]> GetReportPdfAsync(string jobId)
        {
            var response = await _http.GetAsync($"{_base}/report/{jobId}/pdf");

            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync();
                throw new Exception($"API error {response.StatusCode}: {error}");
            }

            return await response.Content.ReadAsByteArrayAsync();
        }

        public async Task<bool> HealthCheckAsync()
        {
            try
            {
                var response = await _http.GetAsync($"{_base}/health");
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }
    }
}