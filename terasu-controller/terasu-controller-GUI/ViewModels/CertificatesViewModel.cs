using ReactiveUI;
using terasu_controller_GUI.Services;
using Terasu.Controller.Core.CA;
using terasu_controller_core.Config;

namespace terasu_controller_GUI.ViewModels;

public sealed class CertificatesViewModel : ViewModelBase
{
    private readonly ConfigService _cfg = new();
    private readonly ICaManager _ca = new CaManager();
    private readonly ConfigManager _mgr = new();

    private string _certPath = string.Empty;
    public string CertPath { get => _certPath; private set => this.RaiseAndSetIfChanged(ref _certPath, value); }

    private string _thumbprint = string.Empty;
    public string Thumbprint { get => _thumbprint; private set => this.RaiseAndSetIfChanged(ref _thumbprint, value); }

    public ReactiveCommand<System.Reactive.Unit, System.Reactive.Unit> Generate { get; }
    public ReactiveCommand<System.Reactive.Unit, System.Reactive.Unit> Install { get; }

    public CertificatesViewModel()
    {
        var cfg = _cfg.Load();
        CertPath = cfg.Ca.CertFile;
        Generate = ReactiveCommand.CreateFromTask<System.Reactive.Unit, System.Reactive.Unit>(async _ => { await _ca.EnsureFilesAsync(cfg.Ca.CertFile, cfg.Ca.KeyFile); Thumbprint = (await _ca.GetThumbprintAsync(cfg.Ca.CertFile)) ?? string.Empty; return System.Reactive.Unit.Default; });
        Install = ReactiveCommand.CreateFromTask<System.Reactive.Unit, System.Reactive.Unit>(async _ => { await _ca.InstallAsync(cfg.Ca.CertFile); return System.Reactive.Unit.Default; });
        _ = Generate.Execute();
    }
}


