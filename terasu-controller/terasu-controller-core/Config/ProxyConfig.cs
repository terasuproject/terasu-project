using System.Text;

namespace terasu_controller_core.Config;

public sealed class ProxyConfig
{
    public string Listen { get; set; } = "127.0.0.1:8080";
    public string Mode { get; set; } = "list"; // all | list
    public List<string> InterceptList { get; set; } = new();
    public CaSection Ca { get; set; } = new();
    public SecuritySection Security { get; set; } = new();
    public LimitsSection Limits { get; set; } = new();
    public LoggingSection Logging { get; set; } = new();
    public MetricsSection Metrics { get; set; } = new();
    public DnsSection Dns { get; set; } = new();

    public sealed class CaSection
    {
        public string CertFile { get; set; } = string.Empty;
        public string KeyFile { get; set; } = string.Empty;
        public bool AutoGenerate { get; set; } = true;
    }

    public sealed class SecuritySection
    {
        public BasicAuthSection BasicAuth { get; set; } = new();

        public sealed class BasicAuthSection
        {
            public bool Enabled { get; set; }
            public string Username { get; set; } = string.Empty;
            public string Password { get; set; } = string.Empty;
        }
    }

    public sealed class LimitsSection
    {
        public int MaxConns { get; set; } = 4096;
        public string ReadTimeout { get; set; } = "15s";
        public string WriteTimeout { get; set; } = "30s";
    }

    public sealed class LoggingSection
    {
        public string Level { get; set; } = "info";
    }

    public sealed class MetricsSection
    {
        public string Addr { get; set; } = "127.0.0.1:9090";
    }

    public sealed class DnsSection
    {
        public string Mode { get; set; } = "auto"; // auto|terasu|system
    }

    public static ProxyConfig FromYaml(string _)
    {
        // 简化：当前版本不解析现有 YAML，统一返回默认配置。
        return new ProxyConfig();
    }

    public string ToYaml()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"listen: {Listen}");
        sb.AppendLine($"mode: {Mode}");
        sb.AppendLine("intercept_list:");
        foreach (var d in InterceptList)
            sb.AppendLine($"  - {d}");
        sb.AppendLine("ca:");
        sb.AppendLine($"  cert_file: {Ca.CertFile}");
        sb.AppendLine($"  key_file: {Ca.KeyFile}");
        sb.AppendLine($"  auto_generate: {(Ca.AutoGenerate ? "true" : "false")}");
        sb.AppendLine("security:");
        sb.AppendLine("  basic_auth:");
        sb.AppendLine($"    enabled: {(Security.BasicAuth.Enabled ? "true" : "false")}");
        sb.AppendLine($"    username: \"{Security.BasicAuth.Username}\"");
        sb.AppendLine($"    password: \"{Security.BasicAuth.Password}\"");
        sb.AppendLine("limits:");
        sb.AppendLine($"  max_conns: {Limits.MaxConns}");
        sb.AppendLine($"  read_timeout: {Limits.ReadTimeout}");
        sb.AppendLine($"  write_timeout: {Limits.WriteTimeout}");
        sb.AppendLine("logging:");
        sb.AppendLine($"  level: {Logging.Level}");
        sb.AppendLine("metrics:");
        sb.AppendLine($"  addr: {Metrics.Addr}");
        sb.AppendLine("dns:");
        sb.AppendLine($"  mode: {Dns.Mode}");
        return sb.ToString();
    }
}



