using System.Net.Http;

namespace Terasu.Controller.Core.Health
{
    public sealed class HealthClient
    {
        private readonly HttpClient _http = new();
        private readonly Uri _base;

        public HealthClient(string baseAddress = "http://127.0.0.1:9090")
        {
            _base = new Uri(baseAddress.TrimEnd('/'));
        }

        public async Task<bool> CheckAsync(CancellationToken ct = default)
        {
            try
            {
                using HttpResponseMessage resp = await _http.GetAsync(new Uri(_base, "/healthz"), ct);
                return resp.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }
    }
}
