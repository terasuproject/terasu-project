using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Terasu.Controller.Core.Platform;

namespace Terasu.Controller.Core.CA;

public sealed class CaManager : ICaManager
{
    public async Task EnsureFilesAsync(string certFile, string? keyFile = null, CancellationToken ct = default)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(certFile)!);
        if (File.Exists(certFile)) return;

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=terasu-proxy CA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));

        var pem = ExportToPem(cert);
        await File.WriteAllTextAsync(certFile, pem, ct);
        if (!string.IsNullOrEmpty(keyFile))
        {
            var keyPem = ExportKeyToPem(rsa);
            await File.WriteAllTextAsync(keyFile!, keyPem, ct);
        }
    }

    public Task<string?> GetThumbprintAsync(string certFile, CancellationToken ct = default)
    {
        using var cert = X509Certificate2.CreateFromPem(File.ReadAllText(certFile));
        return Task.FromResult<string?>(cert.Thumbprint);
    }

    public async Task<bool> InstallAsync(string certFile, CancellationToken ct = default)
    {
        if (Os.IsWindows)
        {
            return await Run("certutil", $"-addstore -f root \"{certFile}\"", ct) == 0;
        }
        if (Os.IsMacOS)
        {
            return await Run("security", $"add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \"{certFile}\"", ct) == 0;
        }
        if (Os.IsLinux)
        {
            var dir = "/usr/local/share/ca-certificates";
            var dst = $"{dir}/terasu-proxy.crt";
            // Ensure directory exists, copy as .crt, refresh cert store
            var rc = await Run("sh", $"-lc 'mkdir -p {dir} && cp \"{certFile}\" {dst} && (command -v update-ca-certificates >/dev/null 2>&1 && update-ca-certificates --fresh || true)'", ct);
            return rc == 0;
        }
        return false;
    }

    public async Task<bool> UninstallAsync(string? thumbprint = null, string? installedPath = null, CancellationToken ct = default)
    {
        if (Os.IsWindows && thumbprint != null)
            return await Run("powershell", $"-Command Remove-Item -Path Cert:\\LocalMachine\\Root\\{thumbprint}", ct) == 0;
        if (Os.IsMacOS && thumbprint != null)
            return await Run("security", $"delete-certificate -Z {thumbprint}", ct) == 0;
        if (Os.IsLinux)
        {
            var path = installedPath ?? "/usr/local/share/ca-certificates/terasu-proxy.crt";
            var rm = await Run("sh", $"-lc 'rm -f {path} && update-ca-certificates'", ct);
            return rm == 0;
        }
        return false;
    }

    static string ExportToPem(X509Certificate2 cert)
    {
        var b = cert.Export(X509ContentType.Cert);
        return "-----BEGIN CERTIFICATE-----\n" + Convert.ToBase64String(b, Base64FormattingOptions.InsertLineBreaks) + "\n-----END CERTIFICATE-----\n";
    }

    static string ExportKeyToPem(RSA rsa)
    {
        var pkcs1 = rsa.ExportRSAPrivateKey();
        return "-----BEGIN RSA PRIVATE KEY-----\n" + Convert.ToBase64String(pkcs1, Base64FormattingOptions.InsertLineBreaks) + "\n-----END RSA PRIVATE KEY-----\n";
    }

    static async Task<int> Run(string file, string args, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(file, args) { RedirectStandardError = true, RedirectStandardOutput = true, UseShellExecute = false };
        using var p = Process.Start(psi)!;
        await p.WaitForExitAsync(ct);
        return p.ExitCode;
    }
}



