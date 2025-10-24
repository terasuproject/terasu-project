using terasu_controller_core.Config;

namespace terasu_controller_GUI.Services;

public sealed class ConfigService
{
    private readonly ConfigManager _mgr;
    public ConfigService() { _mgr = new ConfigManager(); }

    public ProxyConfig Load() => _mgr.LoadOrDefault();
    public void Save(ProxyConfig cfg) => _mgr.Save(cfg);
    public string ConfigPath => _mgr.ConfigPath;
}



