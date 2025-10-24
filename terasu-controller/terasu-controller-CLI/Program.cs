using terasu_controller_core.Config;
using terasu_controller_core.Proxy;
using Terasu.Controller.Core.CA;
using Terasu.Controller.Core.Health;

var cfgMgr = new ConfigManager();
var cfg = cfgMgr.LoadOrDefault();

string binPath = Environment.GetEnvironmentVariable("TERASU_PROXY_BIN")
                 ?? Path.Combine(AppContext.BaseDirectory, "terasu-proxy");

var proxy = new ProxyManager(binPath, cfgMgr.ConfigPath);
var ca = new CaManager();
var health = new HealthClient(cfg.Metrics.Addr.StartsWith("http") ? cfg.Metrics.Addr : $"http://{cfg.Metrics.Addr}");

if (args.Length == 0) { PrintUsage(); return; }
switch (args[0])
{
    case "start":
    {
        cfgMgr.Save(cfg); // ensure config file exists for terasu-proxy
        await proxy.StartAsync(cfg.Dns.Mode, disableIPv6: true);
        Console.WriteLine("started");
        break;
    }
    case "stop":
        await proxy.StopAsync();
        Console.WriteLine("stopped");
        break;
    case "status":
        Console.WriteLine(await proxy.IsRunningAsync() ? "running" : "stopped");
        break;
    case "install-ca":
    {
        await ca.EnsureFilesAsync(cfg.Ca.CertFile, cfg.Ca.KeyFile);
        var ok = await ca.InstallAsync(cfg.Ca.CertFile);
        Console.WriteLine(ok ? "ca installed" : "ca install failed");
        break;
    }
    case "uninstall-ca":
    {
        var thumb = await ca.GetThumbprintAsync(cfg.Ca.CertFile);
        var ok = await ca.UninstallAsync(thumbprint: thumb);
        Console.WriteLine(ok ? "ca uninstalled" : "ca uninstall failed");
        break;
    }
    case "health":
    {
        Console.WriteLine(await health.CheckAsync() ? "ok" : "down");
        break;
    }
    case "set-mode":
    {
        if (args.Length < 2) { Console.WriteLine("need value: all|list"); return; }
        cfg.Mode = args[1];
        cfgMgr.Save(cfg);
        Console.WriteLine("mode updated");
        break;
    }
    case "add-domain":
    {
        if (args.Length < 2) { Console.WriteLine("need domain"); return; }
        if (!cfg.InterceptList.Contains(args[1])) cfg.InterceptList.Add(args[1]);
        cfgMgr.Save(cfg);
        Console.WriteLine("added");
        break;
    }
    case "remove-domain":
    {
        if (args.Length < 2) { Console.WriteLine("need domain"); return; }
        cfg.InterceptList.RemoveAll(d => string.Equals(d, args[1], StringComparison.OrdinalIgnoreCase));
        cfgMgr.Save(cfg);
        Console.WriteLine("removed");
        break;
    }
    case "list-domains":
    {
        foreach (var d in cfg.InterceptList) Console.WriteLine(d);
        break;
    }
    case "set-dns-mode":
    {
        if (args.Length < 2) { Console.WriteLine("need value: auto|terasu|system"); return; }
        cfg.Dns.Mode = args[1];
        cfgMgr.Save(cfg);
        Console.WriteLine("dns mode updated");
        break;
    }
    case "restart":
    {
        await proxy.StopAsync();
        cfgMgr.Save(cfg);
        await proxy.StartAsync(cfg.Dns.Mode, disableIPv6: true);
        Console.WriteLine("restarted");
        break;
    }
    case "show-ca":
    {
        await ca.EnsureFilesAsync(cfg.Ca.CertFile, cfg.Ca.KeyFile);
        var tp = await ca.GetThumbprintAsync(cfg.Ca.CertFile);
        Console.WriteLine($"ca: {cfg.Ca.CertFile}\nthumbprint: {tp}");
        break;
    }
    case "enable-basic-auth":
    {
        if (args.Length < 3) { Console.WriteLine("need: <user> <pass>"); return; }
        cfg.Security.BasicAuth.Enabled = true;
        cfg.Security.BasicAuth.Username = args[1];
        cfg.Security.BasicAuth.Password = args[2];
        cfgMgr.Save(cfg);
        Console.WriteLine("basic auth enabled");
        break;
    }
    case "disable-basic-auth":
    {
        cfg.Security.BasicAuth.Enabled = false;
        cfgMgr.Save(cfg);
        Console.WriteLine("basic auth disabled");
        break;
    }
    case "set-listen":
    {
        if (args.Length < 2) { Console.WriteLine("need: <host:port>"); return; }
        cfg.Listen = args[1];
        cfgMgr.Save(cfg);
        Console.WriteLine("listen updated");
        break;
    }
    case "set-metrics-addr":
    {
        if (args.Length < 2) { Console.WriteLine("need: <host:port>"); return; }
        cfg.Metrics.Addr = args[1];
        cfgMgr.Save(cfg);
        Console.WriteLine("metrics addr updated");
        break;
    }
    default:
        PrintUsage();
        break;
}

static void PrintUsage()
{
    Console.WriteLine("usage: start|stop|status|install-ca|uninstall-ca|health|set-mode <all|list>|add-domain <d>|remove-domain <d>|list-domains|set-dns-mode <auto|terasu|system>");
}



