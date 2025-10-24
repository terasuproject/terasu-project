using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using terasu_controller_GUI.Models;

namespace terasu_controller_GUI.Services
{
    public sealed class MetricsService
    {
        private readonly HttpClient _http;
        private readonly Uri _base;
        private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

        public MetricsService(string baseAddress)
        {
            _http = new HttpClient();
            _http.Timeout = Timeout.InfiniteTimeSpan; // allow SSE to stream indefinitely
            _base = new Uri(baseAddress.TrimEnd('/'));
        }

        public Task<MetricsSnapshot?> GetSnapshotAsync(CancellationToken ct = default)
        {
            return _http.GetFromJsonAsync<MetricsSnapshot>(new Uri(_base, "/metrics"), JsonOpts, ct);
        }

        public async Task SubscribeLogsAsync(Action<RequestEvent> onEvent, CancellationToken ct = default)
        {
            using HttpRequestMessage req = new(HttpMethod.Get, new Uri(_base, "/logs"));
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
            using HttpResponseMessage resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            resp.EnsureSuccessStatusCode();
            using Stream stream = await resp.Content.ReadAsStreamAsync(ct);
            using StreamReader reader = new(stream);
            while (!reader.EndOfStream && !ct.IsCancellationRequested)
            {
                string? line = await reader.ReadLineAsync();
                if (line == null) break;
                if (line.StartsWith("data: "))
                {
                    string json = line[6..];
                    RequestEvent? ev = JsonSerializer.Deserialize<RequestEvent>(json, JsonOpts);
                    if (ev != null) onEvent(ev);
                }
            }
        }
    }
}
