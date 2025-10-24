using System.Threading;
using System.Threading.Tasks;
using terasu_controller_core.Config;
using terasu_controller_core.Proxy;

namespace terasu_controller_GUI.Services;

public sealed class ProxyControlService
{
    private readonly ConfigManager _cfgMgr;
    private readonly IProxyManager _proxy;

    public ProxyControlService()
    {
        _cfgMgr = new ConfigManager();
        var binPath = System.Environment.GetEnvironmentVariable("TERASU_PROXY_BIN") ?? System.IO.Path.Combine(System.AppContext.BaseDirectory, "terasu-proxy");
        _proxy = new ProxyManager(binPath, _cfgMgr.ConfigPath);
    }

    public Task StartAsync(string? dnsMode = null, bool disableIPv6 = true, CancellationToken ct = default)
        => _proxy.StartAsync(dnsMode, disableIPv6, ct);
    public Task StopAsync(CancellationToken ct = default) => _proxy.StopAsync(ct);
    public Task<bool> IsRunningAsync(CancellationToken ct = default) => _proxy.IsRunningAsync(ct);
    public Task<int?> GetPidAsync(CancellationToken ct = default) => _proxy.GetProcessIdAsync(ct);
    public ConfigManager Configs => _cfgMgr;

    public async Task RestartAsync(CancellationToken ct = default)
    {
        var cfg = _cfgMgr.LoadOrDefault();
        await _proxy.StopAsync(ct);
        await _proxy.StartAsync(cfg.Dns.Mode, true, ct);
    }
}


