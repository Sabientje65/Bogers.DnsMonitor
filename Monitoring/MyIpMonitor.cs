using Bogers.DnsMonitor.Dns;
using Bogers.DnsMonitor.Pushover;
using Microsoft.Extensions.Options;

namespace Bogers.DnsMonitor.Monitoring;

public class PublicIPService : IDisposable
{
    private readonly HttpClient _client;

    public PublicIPService(IHttpClientFactory httpClientFactory)
    {
        _client = httpClientFactory.CreateClient("public-ip");
        _client.BaseAddress = new Uri("https://api.ipify.org");
    }

    /// <summary>
    /// Obtain the public IP address of the current device
    /// </summary>
    /// <returns>Current device's public IP</returns>
    public async Task<string> MyIP() => await _client.GetStringAsync("/");

    public void Dispose()
    {
        _client.Dispose();
    }
}

public class MyPublicIPMonitor : TimedBackgroundService
{
    private readonly IServiceProvider _services;
    
    protected override TimeSpan Interval => TimeSpan.FromMinutes(1);
    
    public MyPublicIPMonitor(ILogger<MyPublicIPMonitor> logger, IServiceProvider services) : base(logger)
    {
        _services = services;
    }

    protected override Task Run(CancellationToken stoppingToken)
    {
        using var serviceScope = _services.CreateScope();
        var services = serviceScope.ServiceProvider;

        var pushover = services.GetRequiredService<PushoverClient>();
        return Task.CompletedTask;
    }
}

public class Monitor : TimedBackgroundService
{
    protected override TimeSpan Interval => TimeSpan.FromMinutes(1);

    private readonly ILogger _logger;
    private readonly IServiceProvider _services;

    public Monitor(ILogger<Monitor> logger, IServiceProvider services) : base(logger)
    {
        _logger = logger;
        _services = services;
    }
    
    protected override Task Run(CancellationToken stoppingToken)
    {
        throw new NotImplementedException();
    }

    private async Task NotifyPublicIPChange(
        EventContext ctx,
        string oldIP, 
        string newIP
    )
    {
        var pushover = ctx.Service<PushoverClient>();
        await pushover.SendMessage(PushoverMessage.Text("Public IP", $"IP changed from {oldIP} to {newIP}"));
    }

    private async Task NotifyDomainIPChange(
        EventContext ctx,
        string domain,
        string oldIP,
        string newIP
    )
    {
        
    }
    
    private class EventContext : IDisposable
    {
        private readonly IServiceScope _scopedServices;

        public EventContext(IServiceProvider services) => _scopedServices = services.CreateScope();

        public TService Service<TService>() => _scopedServices.ServiceProvider.GetRequiredService<TService>();

        public void Dispose() => _scopedServices.Dispose();
    }
}

// to consider: two event types, domainName -> newIP, oldIP -> newIP?
// canHandle on differing notifiers
// alternative, notifier aware message -> have messages determine their own format
// class IPChangedEvent
// {
//     public string OldIP { get; set; }
//
//     public string NewIP { get; set; }
//
//     public string DomainName { get; set; }
// }
//
// class MyIPMonitor
// {
//     
// }
//
// class DomainIPMonitor
// {
//     private readonly DnsResolver _dnsResolver;
//
//     public DomainIPMonitor(DnsResolver dnsResolver)
//     {
//         _dnsResolver = dnsResolver;
//     }
// }
//
// interface INotifier
// {
//     Task Notify(IPChangedEvent evt);
// }
//
// // public class PushoverNotifierConfiguration
// // {
// //     public string DomainName { get; }
// // }
//
// class PushoverNotifier : INotifier, IDisposable
// {
//     // make destination configurable? -> fun for a later addition
//     private readonly PushoverClient _pushover;
//
//     // private readonly PushoverNotifierConfiguration _config;
//     
//     public PushoverNotifier(
//         PushoverClient pushover
//         // IOptions<PushoverNotifierConfiguration> config
//     )
//     {
//         _pushover = pushover;
//         // _config = config.Value;
//     }
//
//     public async Task Notify(IPChangedEvent evt)
//     {
//         // if (!CanNotify(evt)) return;
//         
//         
//         
//         await _pushover.SendMessage(PushoverMessage.Text($"IP changed"));
//     }
//
//     public void Dispose() => _pushover.Dispose();
//
//     // private bool CanNotify(IPChangedEvent evt) => !String.IsNullOrEmpty(evt.DomainName) && 
//     //                                               evt.DomainName.Equals(_config.DomainName, StringComparison.OrdinalIgnoreCase);
// }
//
// class TransipNotifier
// {
//     
// }
//
//
// class TraefikConfiguration
// {
//     public string File { get; set; }
// }
//
// /// <summary>
// /// Update all traefik configurations in the given 
// /// </summary>
// class TraefikConfigNotifier
// {
//     public TraefikConfigNotifier()
//     {
//         
//     }
//     
//     // OldIP NewIP
//     
//     
// }

