using System.Collections.ObjectModel;
using ReactiveUI;
using terasu_controller_GUI.Services;
using terasu_controller_core.Config;

namespace terasu_controller_GUI.ViewModels
{
    public sealed class RulesViewModel : ViewModelBase
    {
        private ProxyConfig _config;

        public ObservableCollection<string> Domains { get; } = new();
        public string Mode
        {
            get => _config.Mode;
            set
            {
                _config.Mode = value;
                this.RaisePropertyChanged();
            }
        }

        private string _newDomain = string.Empty;
        public string NewDomain { get => _newDomain; set => this.RaiseAndSetIfChanged(ref _newDomain, value); }

        public ReactiveCommand<System.Reactive.Unit, System.Reactive.Unit> AddDomain { get; }
        public ReactiveCommand<string, System.Reactive.Unit> RemoveDomain { get; }
        public ReactiveCommand<System.Reactive.Unit, System.Reactive.Unit> Save { get; }
        public ReactiveCommand<System.Reactive.Unit, System.Reactive.Unit> SaveAndRestart { get; }

        public RulesViewModel()
        {
            ConfigService cfgSvc = new();
            _config = cfgSvc.Load();
            foreach (string d in _config.InterceptList) Domains.Add(d);
            AddDomain = ReactiveCommand.Create<System.Reactive.Unit, System.Reactive.Unit>(_ =>
            {
                string d = NewDomain.Trim();
                if (!string.IsNullOrEmpty(d) && !Domains.Contains(d)) Domains.Add(d);
                NewDomain = string.Empty;
                return System.Reactive.Unit.Default;
            });
            RemoveDomain = ReactiveCommand.Create<string, System.Reactive.Unit>(d =>
            {
                Domains.Remove(d);
                return System.Reactive.Unit.Default;
            });
            ProxyControlService ctl = new();
            Save = ReactiveCommand.Create<System.Reactive.Unit, System.Reactive.Unit>(_ =>
            {
                _config.InterceptList = new System.Collections.Generic.List<string>(Domains);
                cfgSvc.Save(_config);
                return System.Reactive.Unit.Default;
            });
            SaveAndRestart = ReactiveCommand.CreateFromTask<System.Reactive.Unit, System.Reactive.Unit>(async _ =>
            {
                _config.InterceptList = new System.Collections.Generic.List<string>(Domains);
                cfgSvc.Save(_config);
                await ctl.RestartAsync();
                return System.Reactive.Unit.Default;
            });
        }
    }
}
