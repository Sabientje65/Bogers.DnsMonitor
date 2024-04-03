using Bogers.DnsMonitor.Dns;
using Bogers.DnsMonitor.Monitoring;
using Bogers.DnsMonitor.Pushover;
using Bogers.DnsMonitor.Transip;
using Microsoft.Extensions.Logging.Console;

var builder = Host.CreateApplicationBuilder();

builder.Logging.AddSimpleConsole(opts => {
    opts.SingleLine = true;
    opts.ColorBehavior = LoggerColorBehavior.Enabled;
    opts.TimestampFormat = "[yyyy-MM-dd hh:mm:ss]";
});

builder.Services
    .AddSingleton<SqliteResolverCache>(_ =>
    {
        var connectionString = builder.Configuration.GetValue<string?>("dns:cache:connectionstring")!;
        var resolverCache = String.IsNullOrEmpty(connectionString) ?
            new SqliteResolverCache() :
            new SqliteResolverCache(connectionString);
        
        resolverCache.Initialize();
        return resolverCache;
    })
    .AddSingleton<TraefikConfigUpdater>(services => new TraefikConfigUpdater(services.GetRequiredService<ILogger<TraefikConfigUpdater>>())
    {
        // wanna have this working but also wanna go to bed xd
        Path = "/data/traefik-whitelist.yml"
        // Path = "D:\\Data\\traefik-whitelist.yml"
    })
    .AddSingleton<DnsResolver>()
    .AddScoped<TransipClient>()
    .AddSingleton<TransipAuthenticationService>()
    .AddScoped<PushoverClient>();
    
builder.Services.AddHttpClient("pushover", client => client.BaseAddress = new Uri("https://api.pushover.net/"));
builder.Services.AddHttpClient("transip", client => client.BaseAddress = new Uri("https://api.transip.nl/"));
builder.Services.AddHttpClient("myip", client => client.BaseAddress = new Uri("https://api.ipify.org/"));

builder.Services.AddOptions<TransipConfiguration>()
    .BindConfiguration("Transip");

builder.Services.AddOptions<PushoverConfiguration>()
    .BindConfiguration("Pushover");

builder.Services.AddHostedService<MyDomainIPMonitorService>();
builder.Services.AddHostedService<ExternalDomainIPMonitorService>(services => new ExternalDomainIPMonitorService( services.GetRequiredService<ILogger<ExternalDomainIPMonitorService>>(), services) {
    // letsencrypt -> used for obtain certificates, *assumed* to never ever change :-)
    Domain = "acme-v02.api.letsencrypt.org"
});

var host = builder.Build();
await host.RunAsync();

// await host.Services.GetRequiredService<TransipClient>().GetEntries("bogers.online");
