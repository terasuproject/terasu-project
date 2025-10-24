using System.Reactive;
using System.Reactive.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using ReactiveUI;
using terasu_controller_GUI.Models;
using terasu_controller_GUI.Services;

namespace terasu_controller_GUI.ViewModels;

public sealed class DashboardViewModel : ViewModelBase
{
    private readonly MetricsService _metrics;
    private readonly ObservableAsPropertyHelper<MetricsSnapshot?> _snapshot;

    public MetricsSnapshot? Snapshot => _snapshot.Value;
    public ReactiveCommand<Unit, Unit> Refresh { get; }

    public DashboardViewModel(string baseAddress)
    {
        _metrics = new MetricsService(baseAddress);
        Refresh = ReactiveCommand.CreateFromTask(RefreshAsync);
        _snapshot = Refresh.Select(_ => _last).ToProperty(this, x => x.Snapshot);
        Dispatcher.UIThread.Post(async () => await Refresh.Execute());
    }

    private MetricsSnapshot? _last;
    private async Task RefreshAsync()
    {
        try
        {
            _last = await _metrics.GetSnapshotAsync(CancellationToken.None);
            this.RaisePropertyChanged(nameof(Snapshot));
        }
        catch { /* ignore */ }
    }
}





