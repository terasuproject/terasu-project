namespace Terasu.Controller.Core.SystemProxy
{
    public interface ISystemProxyManager
    {
        Task<bool> EnableAsync(string host, int port, CancellationToken ct = default);
        Task<bool> DisableAsync(CancellationToken ct = default);
    }
}
