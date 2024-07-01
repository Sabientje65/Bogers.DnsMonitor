using Bogers.DnsMonitor.Dns;
using Bogers.DnsMonitor.Monitoring;
using Bogers.DnsMonitor.Pushover;
using Bogers.DnsMonitor.Traefik;
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
        // todo: pull from env/config
        Path = "/data/traefik-whitelist.yml"
    })
    .AddSingleton<DnsResolver>()
    .AddScoped<TransipClient>()
    .AddSingleton<TransipAuthenticationService>()
    .AddScoped<PushoverClient>()
    .AddScoped<TraefikClient>();
    
builder.Services.AddHttpClient("pushover", client => client.BaseAddress = new Uri("https://api.pushover.net/"));
builder.Services.AddHttpClient("transip", client => client.BaseAddress = new Uri("https://api.transip.nl/"));
builder.Services.AddHttpClient("traefik", client => client.BaseAddress = new Uri("traefik")); // https://traefik.primagen.org/
builder.Services.AddHttpClient("myip", client => client.BaseAddress = new Uri("https://api.ipify.org/"));

builder.Services.AddOptions<TransipConfiguration>()
    .BindConfiguration("Transip");

builder.Services.AddOptions<PushoverConfiguration>()
    .BindConfiguration("Pushover");

builder.Services.AddHostedService<MyDomainIPMonitorService>(services => new MyDomainIPMonitorService(services.GetRequiredService<ILogger<MyDomainIPMonitorService>>(), services, services.GetRequiredService<IHttpClientFactory>())
{
    Domain = "primagen.org"
});

builder.Services.AddHostedService<TraefikDnsSynchronisationService>(services => new TraefikDnsSynchronisationService(services.GetRequiredService<ILogger<TraefikDnsSynchronisationService>>(), services)
{
    Domain = "primagen.org"
});

builder.Services.AddHostedService<ExternalDomainIPMonitorService>(services => new ExternalDomainIPMonitorService( services.GetRequiredService<ILogger<ExternalDomainIPMonitorService>>(), services) {
    // letsencrypt -> used for obtain certificates, *assumed* to never ever change :-)
    Domain = "acme-v02.api.letsencrypt.org"
});

var host = builder.Build();
await host.RunAsync();
