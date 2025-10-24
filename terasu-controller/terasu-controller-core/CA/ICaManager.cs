namespace Terasu.Controller.Core.CA;

public interface ICaManager
{
    Task EnsureFilesAsync(string certFile, string? keyFile = null, CancellationToken ct = default);
    Task<string?> GetThumbprintAsync(string certFile, CancellationToken ct = default);
    Task<bool> InstallAsync(string certFile, CancellationToken ct = default);
    Task<bool> UninstallAsync(string? thumbprint = null, string? installedPath = null, CancellationToken ct = default);
}



