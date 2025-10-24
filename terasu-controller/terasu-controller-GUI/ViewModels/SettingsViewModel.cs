using ReactiveUI;
using terasu_controller_core.Config;
using terasu_controller_GUI.Services;

namespace terasu_controller_GUI.ViewModels;

public sealed class SettingsViewModel : ViewModelBase
{
    private readonly ConfigService _cfg = new();
    private ProxyConfig _c;
    public string Listen { get => _c.Listen; set { _c.Listen = value; this.RaisePropertyChanged(); } }
    public string MetricsAddr { get => _c.Metrics.Addr; set { _c.Metrics.Addr = value; this.RaisePropertyChanged(); } }
    public string DnsMode { get => _c.Dns.Mode; set { _c.Dns.Mode = value; this.RaisePropertyChanged(); } }
    public bool BasicAuthEnabled { get => _c.Security.BasicAuth.Enabled; set { _c.Security.BasicAuth.Enabled = value; this.RaisePropertyChanged(); } }
    public string BasicUser { get => _c.Security.BasicAuth.Username; set { _c.Security.BasicAuth.Username = value; this.RaisePropertyChanged(); } }
    public string BasicPass { get => _c.Security.BasicAuth.Password; set { _c.Security.BasicAuth.Password = value; this.RaisePropertyChanged(); } }

    public ReactiveCommand<System.Reactive.Unit, System.Reactive.Unit> Save { get; }
    public ReactiveCommand<System.Reactive.Unit, System.Reactive.Unit> SaveAndRestart { get; }

    public SettingsViewModel()
    {
        _c = _cfg.Load();
        var ctl = new ProxyControlService();
        Save = ReactiveCommand.Create<System.Reactive.Unit, System.Reactive.Unit>(_ => { _cfg.Save(_c); return System.Reactive.Unit.Default; });
        SaveAndRestart = ReactiveCommand.CreateFromTask<System.Reactive.Unit, System.Reactive.Unit>(async _ => { _cfg.Save(_c); await ctl.RestartAsync(); return System.Reactive.Unit.Default; });
    }
}


