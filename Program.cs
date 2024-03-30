using Bogers.DnsMonitor;
using Bogers.DnsMonitor.Dns;

await DnsResolver.QueryResourceRecords("bogers.online");

// var builder = Host.CreateApplicationBuilder(args);
// builder.Services.AddHostedService<MainWorker>();
//
// var host = builder.Build();
// host.Run();