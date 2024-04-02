using Bogers.DnsMonitor.Dns;
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
    .AddSingleton<TransipClient>()
    .AddHttpClient();

builder.Services.AddOptions<TransipConfiguration>()
    .BindConfiguration("Transip");

var host = builder.Build();
await host.Services.GetRequiredService<TransipClient>().Send();

// var result = await .Services.GetService<DnsResolver>().ResolveIPV4("chapoco.bogers.online");
// Console.WriteLine("Result: " + result);