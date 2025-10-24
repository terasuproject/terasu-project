using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using ReactiveUI;
using terasu_controller_GUI.Services;
using System.Threading;
using System.Threading.Tasks;

namespace terasu_controller_GUI.ViewModels;

public sealed class DiagnosticsViewModel : ViewModelBase
{
    private string _result = string.Empty;
    public string Result { get => _result; set => this.RaiseAndSetIfChanged(ref _result, value); }

    private bool _isBusy;
    public bool IsBusy { get => _isBusy; set => this.RaiseAndSetIfChanged(ref _isBusy, value); }

    public ReactiveCommand<System.Reactive.Unit, System.Reactive.Unit> TestDockerHub { get; }
    public ReactiveCommand<System.Reactive.Unit, System.Reactive.Unit> TestGithub { get; }

    public DiagnosticsViewModel()
    {
        TestDockerHub = ReactiveCommand.CreateFromTask<System.Reactive.Unit, System.Reactive.Unit>(async _ => { await RunTestAsync("https://registry-1.docker.io/v2/"); return System.Reactive.Unit.Default; });
        TestGithub = ReactiveCommand.CreateFromTask<System.Reactive.Unit, System.Reactive.Unit>(async _ => { await RunTestAsync("https://github.com/"); return System.Reactive.Unit.Default; });
    }

    private async Task RunTestAsync(string url)
    {
        IsBusy = true;
        try
        {
            using var http = CreateProxiedClient();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(12));
            var sw = System.Diagnostics.Stopwatch.StartNew();
            using var req = new HttpRequestMessage(HttpMethod.Head, url);
            var resp = await http.SendAsync(req, cts.Token);
            sw.Stop();
            Result = $"{url} -> {(int)resp.StatusCode} ({sw.ElapsedMilliseconds} ms)";
        }
        catch (Exception ex)
        {
            Result = $"{url} -> error: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private static HttpClient CreateProxiedClient()
    {
        var cfgSvc = new ConfigService();
        var cfg = cfgSvc.Load();

        var proxyAddr = cfg.Listen.StartsWith("http") ? cfg.Listen : $"http://{cfg.Listen}";
        var handler = new HttpClientHandler
        {
            Proxy = new WebProxy(proxyAddr),
            UseProxy = true,
            AllowAutoRedirect = false,
            ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => ValidateWithCustomCa(cfg.Ca.CertFile, cert)
        };

        if (cfg.Security.BasicAuth.Enabled && !string.IsNullOrEmpty(cfg.Security.BasicAuth.Username))
        {
            (handler.Proxy as WebProxy)!.Credentials = new NetworkCredential(cfg.Security.BasicAuth.Username, cfg.Security.BasicAuth.Password);
        }

        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
    }

    private static bool ValidateWithCustomCa(string caPath, X509Certificate2? serverCert)
    {
        try
        {
            if (serverCert == null) return false;
            if (!File.Exists(caPath)) return false;

            using var ca = X509Certificate2.CreateFromPem(File.ReadAllText(caPath));
            using var leaf = new X509Certificate2(serverCert);
            using var chain = new X509Chain
            {
                ChainPolicy =
                {
                    RevocationMode = X509RevocationMode.NoCheck,
                    RevocationFlag = X509RevocationFlag.EndCertificateOnly,
                    VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority,
                    TrustMode = X509ChainTrustMode.CustomRootTrust
                }
            };
            chain.ChainPolicy.CustomTrustStore.Add(ca);
            return chain.Build(leaf);
        }
        catch
        {
            return false;
        }
    }
}


