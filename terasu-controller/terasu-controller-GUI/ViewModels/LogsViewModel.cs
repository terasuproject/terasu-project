using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using ReactiveUI;
using terasu_controller_GUI.Models;
using terasu_controller_GUI.Services;

namespace terasu_controller_GUI.ViewModels
{
    public sealed class LogsViewModel : ViewModelBase
    {
        private readonly MetricsService _metrics;
        private readonly ObservableCollection<RequestEvent> _all = new();
        public ReadOnlyObservableCollection<RequestEvent> Items { get; }

        private string _filter = string.Empty;
        public string Filter
        {
            get => _filter;
            set
            {
                this.RaiseAndSetIfChanged(ref _filter, value);
                ApplyFilter();
            }
        }

        public ReactiveCommand<System.Reactive.Unit, System.Reactive.Unit> Clear { get; }

        private readonly ObservableCollection<RequestEvent> _view = new();

        public LogsViewModel(string baseAddress)
        {
            _metrics = new MetricsService(baseAddress);
            Items = new ReadOnlyObservableCollection<RequestEvent>(_view);
            Clear = ReactiveCommand.Create(() =>
            {
                _all.Clear();
                _view.Clear();
            });
            _ = Task.Run(RunAsync);
        }

        private async Task RunAsync()
        {
            await _metrics.SubscribeLogsAsync(ev =>
            {
                Dispatcher.UIThread.Post(() =>
                {
                    _all.Add(ev);
                    if (Match(ev, _filter)) _view.Add(ev);
                });
            }, CancellationToken.None);
        }

        private void ApplyFilter()
        {
            _view.Clear();
            foreach (RequestEvent ev in _all.Where(e => Match(e, _filter))) _view.Add(ev);
        }

        private static bool Match(RequestEvent ev, string f)
        {
            if (string.IsNullOrWhiteSpace(f)) return true;
            f = f.ToLowerInvariant();
            return ev.Host.ToLowerInvariant().Contains(f) || ev.Path.ToLowerInvariant().Contains(f) || ev.Method.ToLowerInvariant().Contains(f);
        }
    }
}
