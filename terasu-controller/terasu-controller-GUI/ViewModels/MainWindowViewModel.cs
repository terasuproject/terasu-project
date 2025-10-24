using System;
using ReactiveUI;

namespace terasu_controller_GUI.ViewModels;

public class MainWindowViewModel : ViewModelBase
{
    private string _baseAddress = "http://127.0.0.1:9090";
    public string BaseAddress { get => _baseAddress; set { this.RaiseAndSetIfChanged(ref _baseAddress, value); } }

    public Avalonia.Collections.AvaloniaList<Models.TabPage> Tabs { get; } = new();
    private object _selected = default!;
    public object Selected { get => _selected; set => this.RaiseAndSetIfChanged(ref _selected, value); }

    public MainWindowViewModel()
    {
        Tabs.Add(new Models.TabPage{ Title = "Dashboard", Content = new DashboardViewModel(BaseAddress)});
        Tabs.Add(new Models.TabPage{ Title = "Logs", Content = new LogsViewModel(BaseAddress)});
        Tabs.Add(new Models.TabPage{ Title = "Traffic", Content = new TrafficViewModel(BaseAddress)});
        Tabs.Add(new Models.TabPage{ Title = "Rules", Content = new RulesViewModel()});
        Tabs.Add(new Models.TabPage{ Title = "Settings", Content = new SettingsViewModel()});
        Tabs.Add(new Models.TabPage{ Title = "Certificates", Content = new CertificatesViewModel()});
        Tabs.Add(new Models.TabPage{ Title = "Diagnostics", Content = new DiagnosticsViewModel()});
        Selected = Tabs[0];
    }
}
