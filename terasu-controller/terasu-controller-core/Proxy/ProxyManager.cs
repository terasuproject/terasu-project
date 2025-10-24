using System.Diagnostics;

namespace terasu_controller_core.Proxy
{
    public sealed class ProxyManager : IProxyManager
    {
        private Process? _proc;
        private readonly string _binaryPath;
        private readonly string _configPath;

        public ProxyManager(string binaryPath, string configPath)
        {
            _binaryPath = binaryPath;
            _configPath = configPath;
        }

        public async Task StartAsync(string? dnsMode = null, bool? disableIPv6 = null, CancellationToken ct = default)
        {
            if (_proc != null && !_proc.HasExited) return;
            ProcessStartInfo psi = new(_binaryPath, $"-config \"{_configPath}\"")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            if (!string.IsNullOrWhiteSpace(dnsMode))
                psi.Environment["TERASU_PROXY_DNS_MODE"] = dnsMode;
            if (disableIPv6 == true)
                psi.Environment["GODEBUG"] = "ipv6=0";
            _proc = Process.Start(psi)!;
            // simple delay to allow bind
            await Task.Delay(TimeSpan.FromMilliseconds(150), ct);
        }

        public Task StopAsync(CancellationToken ct = default)
        {
            if (_proc == null) return Task.CompletedTask;
            try
            {
                if (!_proc.HasExited)
                {
                    _proc.Kill(true);
                    _proc.WaitForExit(3000);
                }
            }
            catch
            { /* ignore */
            }
            finally { _proc = null; }
            return Task.CompletedTask;
        }

        public Task<bool> IsRunningAsync(CancellationToken ct = default)
        {
            return Task.FromResult(_proc != null && !_proc.HasExited);
        }

        public Task<int?> GetProcessIdAsync(CancellationToken ct = default)
        {
            int? pid = _proc != null && !_proc.HasExited ? _proc.Id : null;
            return Task.FromResult(pid);
        }
    }
}
