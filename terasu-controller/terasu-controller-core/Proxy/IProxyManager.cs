namespace terasu_controller_core.Proxy
{
    public interface IProxyManager
    {
        Task StartAsync(string? dnsMode = null, bool? disableIPv6 = null, CancellationToken ct = default);
        Task StopAsync(CancellationToken ct = default);
        Task<bool> IsRunningAsync(CancellationToken ct = default);
        Task<int?> GetProcessIdAsync(CancellationToken ct = default);
    }
}
