using System.Diagnostics;
using Terasu.Controller.Core.Platform;

namespace Terasu.Controller.Core.SystemProxy
{
    public sealed class SystemProxyManager : ISystemProxyManager
    {
        public async Task<bool> EnableAsync(string host, int port, CancellationToken ct = default)
        {
            if (Os.IsWindows)
            {
                int ec = await Run("netsh", $"winhttp set proxy {host}:{port}", ct);
                return ec == 0;
            }
            if (Os.IsMacOS)
            {
                // best-effort: apply to all hardware services
                string[] services = new[]
                {
                    "Wi-Fi", "Ethernet"
                };
                bool ok = true;
                foreach (string s in services)
                {
                    ok &= await Run("networksetup", $"-setwebproxy \"{s}\" {host} {port}", ct) == 0;
                    ok &= await Run("networksetup", $"-setsecurewebproxy \"{s}\" {host} {port}", ct) == 0;
                }
                return ok;
            }
            if (Os.IsLinux)
            {
                // GNOME
                int ec1 = await Run("gsettings", $"set org.gnome.system.proxy mode 'manual'", ct);
                int ec2 = await Run("gsettings", $"set org.gnome.system.proxy.http host '{host}'", ct);
                int ec3 = await Run("gsettings", $"set org.gnome.system.proxy.http port {port}", ct);
                int ec4 = await Run("gsettings", $"set org.gnome.system.proxy.https host '{host}'", ct);
                int ec5 = await Run("gsettings", $"set org.gnome.system.proxy.https port {port}", ct);
                return ec1 * ec2 * ec3 * ec4 * ec5 == 0;
            }
            return false;
        }

        public async Task<bool> DisableAsync(CancellationToken ct = default)
        {
            if (Os.IsWindows)
                return await Run("netsh", "winhttp reset proxy", ct) == 0;
            if (Os.IsMacOS)
            {
                string[] services = new[]
                {
                    "Wi-Fi", "Ethernet"
                };
                bool ok = true;
                foreach (string s in services)
                {
                    ok &= await Run("networksetup", $"-setwebproxystate \"{s}\" off", ct) == 0;
                    ok &= await Run("networksetup", $"-setsecurewebproxystate \"{s}\" off", ct) == 0;
                }
                return ok;
            }
            if (Os.IsLinux)
                return await Run("gsettings", "set org.gnome.system.proxy mode 'none'", ct) == 0;
            return false;
        }

        private static async Task<int> Run(string file, string args, CancellationToken ct)
        {
            ProcessStartInfo psi = new(file, args)
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false
            };
            using Process p = Process.Start(psi)!;
            await p.WaitForExitAsync(ct);
            return p.ExitCode;
        }
    }
}
