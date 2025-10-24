using System;
using System.Collections.Generic;

namespace terasu_controller_GUI.Models;

public sealed class RequestEvent
{
    public DateTime Ts { get; set; }
    public string Host { get; set; } = string.Empty;
    public string Method { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public int Code { get; set; }
    public long Ms { get; set; }
    public long BytesIn { get; set; }
    public long BytesOut { get; set; }
}

public sealed class HostStat
{
    public ulong Req { get; set; }
    public ulong BytesIn { get; set; }
    public ulong BytesOut { get; set; }
}

public sealed class MetricsSnapshot
{
    public ulong UptimeSec { get; set; }
    public ulong TotalRequests { get; set; }
    public Dictionary<string, ulong> Codes { get; set; } = new();
    public ulong BytesIn { get; set; }
    public ulong BytesOut { get; set; }
    public Dictionary<string, HostStat> Hosts { get; set; } = new();
}

public sealed class CodeCount
{
    public string Code { get; set; } = string.Empty;
    public ulong Count { get; set; }
}

public sealed class HostReq
{
    public string Host { get; set; } = string.Empty;
    public ulong Req { get; set; }
}


