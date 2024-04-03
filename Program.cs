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

var host = builder.Build();
await host.RunAsync();

// await host.Services.GetRequiredService<TransipClient>().GetEntries("bogers.online");
