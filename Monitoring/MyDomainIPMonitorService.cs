using Bogers.DnsMonitor.Pushover;
using Bogers.DnsMonitor.Transip;

namespace Bogers.DnsMonitor.Monitoring;

// class DomainIPSource
// {
//     private readonly DnsResolver _dnsResolver;
//     private readonly string _domain;
//     
//     public DomainIPSource(DnsResolver dnsResolver, string domain)
//     {
//         _dnsResolver = dnsResolver;
//         _domain = domain;
//     }
//
//     public async Task<string> CurrentIP() => (await _dnsResolver.ResolveIPV4(_domain))!;
// }
//
// public class MyIPSource : IDisposable
// {
//     private readonly HttpClient _client;
//
//     public MyIPSource(IHttpClientFactory clientFactory)
//     {
//         _client = clientFactory.CreateClient("myip");
//     }
//
//     public async Task<string> CurrentIP() => await _client.GetStringAsync("/");
//     
//     public void Dispose()
//     {
//         _client.Dispose();
//     }
// }


/// <summary>
/// Service monitoring current networks public IP, notifying, propagating to DNS provider, etc. when a change occurs
/// </summary>
public class MyDomainIPMonitorService : TimedBackgroundService
{
    private readonly ILogger _logger;
    
    private readonly IServiceProvider _services;
    private readonly IHttpClientFactory _httpClientFactory;

    private const string MyDomain = "bogers.online";
    private string _previous = String.Empty;
    
    protected override TimeSpan Interval => TimeSpan.FromMinutes(1);
    
    public MyDomainIPMonitorService(
        ILogger<MyDomainIPMonitorService> logger, 
        IServiceProvider services, 
        IHttpClientFactory httpClientFactory
    ) : base(logger)
    {
        _logger = logger;
        
        _services = services;
        _httpClientFactory = httpClientFactory;
    }

    protected override async Task Run(CancellationToken stoppingToken)
    {
        using var serviceScope = _services.CreateScope();
        var services = serviceScope.ServiceProvider;

        var pushover = services.GetRequiredService<PushoverClient>();
        var transip = services.GetRequiredService<TransipClient>();

        if (String.IsNullOrEmpty(_previous))
        {
            _previous = await GetInitialIPFromTransip(transip);
            _logger.LogInformation("Initial IP set to {IP}", _previous);
        }
        
        var current = await GetMyCurrentPublicIP();
        _logger.LogDebug("Current IP is: {IP}", current);

        if (String.IsNullOrEmpty(current))
        {
            _logger.LogWarning("Failed to resolve current IP");
            return;
        }
        
        if (current.Equals(_previous)) return;

        _logger.LogInformation("IP changed from {PreviousIP} to {NewIP}, updating DNS records for {MyDomain} in Transip", _previous, current, MyDomain);

        var myDnsEntries = await transip.GetDnsEntries(MyDomain);
        var myOutdatedDnsEntries = myDnsEntries
            .Where(entry => entry.Content.Equals(_previous))
            .ToArray();
        
        // In case of failure, inform prior to performing individual updates, can screw ourselves over in case of a server reboot or w/e mid processing
        // maybe process A record with MyDomain name last?
        await pushover.SendMessage(PushoverMessage.Text(
            "Public IP changed",
            $"IP Changed from {_previous} to {current}\nUpdating the following DNS entries for {MyDomain}\n\n{String.Join("\n\n", myOutdatedDnsEntries.Select(x => $"name: {x.Name}\ntype: {x.Type}"))}"
        ));
        
        foreach (var dnsEntry in myOutdatedDnsEntries)
        {
            if (!dnsEntry.Content.Equals(_previous)) continue;
            
            _logger.LogInformation("Changing content for domain {MyDomain} DNS record with name {Name} and type {Type} to {NewIP}", MyDomain, dnsEntry.Name, dnsEntry.Type, current);
            dnsEntry.Content = current;
            await transip.UpdateEntry(MyDomain, dnsEntry);
        }

        _previous = current;
        
        // todo: update traefik whitelist
    }

    /// <summary>
    /// Read my current IP from transips A record associated with my domain for use as a starting point for monitoring
    /// </summary>
    /// <param name="transip">Transip client</param>
    /// <returns>My current IP</returns>
    private async Task<string> GetInitialIPFromTransip(TransipClient transip)
    {
        _logger.LogDebug("Attempting to resolve initial IP for {MyDomain}", MyDomain);
        
        // we're going to assume we have an A record for our domain matching our domain name
        var myDomainEntries = await transip.GetDnsEntries(MyDomain);
        return myDomainEntries
            .SingleOrDefault(e => 
                e.Type.Equals("A", StringComparison.OrdinalIgnoreCase) && 
                e.Name.Equals(MyDomain, StringComparison.OrdinalIgnoreCase)
            )!
            .Content;
    }

    /// <summary>
    /// Get my current public IP address echoed back by an external service
    /// </summary>
    /// <returns>My public IP</returns>
    private async Task<string> GetMyCurrentPublicIP()
    {
        using var client = _httpClientFactory.CreateClient("myip");
        return await client.GetStringAsync("/");
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

