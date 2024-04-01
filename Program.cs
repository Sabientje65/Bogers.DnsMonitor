using Bogers.DnsMonitor.Dns;

var builder = Host.CreateApplicationBuilder();

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
    .AddSingleton<DnsResolver>();

var result = await builder.Build().Services.GetService<DnsResolver>().ResolveIPV4("chapoco.bogers.online");
Console.WriteLine("Result: " + result);