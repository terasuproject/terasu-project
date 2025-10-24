namespace terasu_controller_core.Config;

public sealed class ConfigManager
{
    public string BaseDir { get; }
    public string ConfigPath => Path.Combine(BaseDir, "config.yaml");
    public string DataDir => Path.Combine(BaseDir, "data");

    public ConfigManager(string? baseDir = null)
    {
        BaseDir = baseDir ?? GetDefaultBaseDir();
        Directory.CreateDirectory(BaseDir);
        Directory.CreateDirectory(DataDir);
    }

    static string GetDefaultBaseDir()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (OperatingSystem.IsMacOS())
            home = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Personal), "Library", "Application Support");
        var dir = Path.Combine(home, "terasu-controller");
        return dir;
    }

    public ProxyConfig LoadOrDefault()
    {
        if (!File.Exists(ConfigPath)) return DefaultConfig();
        var txt = File.ReadAllText(ConfigPath);
        try { return ParseYaml(txt, DefaultConfig()); }
        catch { return DefaultConfig(); }
    }

    public void Save(ProxyConfig cfg)
    {
        File.WriteAllText(ConfigPath, cfg.ToYaml());
    }

    ProxyConfig DefaultConfig() => new ProxyConfig
    {
        Listen = "127.0.0.1:8080",
        Dns = new ProxyConfig.DnsSection{ Mode = "auto" },
        Metrics = new ProxyConfig.MetricsSection{ Addr = "127.0.0.1:9090" },
        Ca = new ProxyConfig.CaSection{ CertFile = Path.Combine(DataDir, "ca.pem") , KeyFile = Path.Combine(DataDir, "ca.key"), AutoGenerate = true },
    };

    static ProxyConfig ParseYaml(string yaml, ProxyConfig cfg)
    {
        string section = ""; string subsection = "";
        bool inList = false;
        foreach (var raw in yaml.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith("#")) continue;
            var indent = raw.Length - raw.TrimStart(' ').Length;
            var t = line.Trim();

            if (indent == 0)
            {
                inList = false; subsection = "";
                if (t.EndsWith(":"))
                {
                    section = t[..^1];
                    continue;
                }
                var (k,v) = SplitKv(t);
                if (k == "listen" && v != null) cfg.Listen = v;
                else if (k == "mode" && v != null) cfg.Mode = v;
                else if (k == "intercept_list") inList = true;
                continue;
            }

            if (inList && t.StartsWith("- "))
            {
                var item = t[2..].Trim().Trim('"');
                if (!string.IsNullOrEmpty(item)) cfg.InterceptList.Add(item);
                continue;
            }

            if (indent == 2)
            {
                if (t.EndsWith(":")) { subsection = t[..^1]; continue; }
                var (k,v) = SplitKv(t);
                switch (section)
                {
                    case "ca":
                        if (k=="cert_file" && v!=null) cfg.Ca.CertFile = v;
                        else if (k=="key_file" && v!=null) cfg.Ca.KeyFile = v;
                        else if (k=="auto_generate" && v!=null) cfg.Ca.AutoGenerate = ToBool(v);
                        break;
                    case "limits":
                        if (k=="max_conns" && int.TryParse(v, out var mc)) cfg.Limits.MaxConns = mc;
                        else if (k=="read_timeout" && v!=null) cfg.Limits.ReadTimeout = v;
                        else if (k=="write_timeout" && v!=null) cfg.Limits.WriteTimeout = v;
                        break;
                    case "logging":
                        if (k=="level" && v!=null) cfg.Logging.Level = v;
                        break;
                    case "metrics":
                        if (k=="addr" && v!=null) cfg.Metrics.Addr = v;
                        break;
                    case "dns":
                        if (k=="mode" && v!=null) cfg.Dns.Mode = v;
                        break;
                }
                continue;
            }

            if (indent == 4 && section == "security" && subsection == "basic_auth")
            {
                var (k,v) = SplitKv(t);
                if (k=="enabled" && v!=null) cfg.Security.BasicAuth.Enabled = ToBool(v);
                else if (k=="username" && v!=null) cfg.Security.BasicAuth.Username = v.Trim('"');
                else if (k=="password" && v!=null) cfg.Security.BasicAuth.Password = v.Trim('"');
            }
        }
        return cfg;
    }

    static (string key, string? val) SplitKv(string line)
    {
        var idx = line.IndexOf(':');
        if (idx < 0) return (line.Trim(), null);
        var k = line[..idx].Trim();
        var v = line[(idx+1)..].Trim();
        if (v.StartsWith("\"") && v.EndsWith("\"")) v = v.Trim('"');
        return (k, v);
    }

    static bool ToBool(string v) => string.Equals(v, "true", StringComparison.OrdinalIgnoreCase) || v == "1" || v == "yes";
}



