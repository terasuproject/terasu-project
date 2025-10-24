using System;
using System.Collections.Generic;
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
    public sealed class TrafficViewModel : ViewModelBase
    {
        private readonly MetricsService _metrics;
        private MetricsSnapshot? _snapshot;
        public MetricsSnapshot? Snapshot { get => _snapshot; private set => this.RaiseAndSetIfChanged(ref _snapshot, value); }

        public ObservableCollection<CodeCount> Codes { get; } = new();
        public ObservableCollection<HostReq> TopHosts { get; } = new();

        public TrafficViewModel(string baseAddress)
        {
            _metrics = new MetricsService(baseAddress);
            _ = Task.Run(PollAsync);
        }

        private async Task PollAsync()
        {
            while (true)
            {
                try
                {
                    MetricsSnapshot? s = await _metrics.GetSnapshotAsync(CancellationToken.None);
                    if (s != null)
                    {
                        Dispatcher.UIThread.Post(() =>
                        {
                            Snapshot = s;
                            Codes.Clear();
                            foreach (KeyValuePair<string, ulong> kv in s.Codes.OrderByDescending(kv => kv.Value).Take(6))
                                Codes.Add(new CodeCount
                                {
                                    Code = kv.Key.ToString(),
                                    Count = kv.Value
                                });
                            TopHosts.Clear();
                            foreach (KeyValuePair<string, HostStat> kv in s.Hosts.OrderByDescending(kv => kv.Value.Req).Take(10))
                                TopHosts.Add(new HostReq
                                {
                                    Host = kv.Key,
                                    Req = kv.Value.Req
                                });
                        });
                    }
                }
                catch { }
                await Task.Delay(2000);
            }
        }
    }
}
