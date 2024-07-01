using Bogers.DnsMonitor.Pushover;
using Bogers.DnsMonitor.Transip;

namespace Bogers.DnsMonitor.Monitoring;

/// <summary>
/// Service monitoring current networks public IP, notifying, propagating to DNS provider, etc. when a change occurs
/// </summary>
public class MyDomainIPMonitorService : TimedBackgroundService
{
    private readonly ILogger _logger;
    
    private readonly IServiceProvider _services;
    private readonly IHttpClientFactory _httpClientFactory;
    private string _previous = String.Empty;
    
    public required string Domain { get; init; }
    
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

    protected override async Task Initialize(CancellationToken stoppingToken)
    {
        using var serviceScope = _services.CreateScope();
        var services = serviceScope.ServiceProvider;
        
        var transip = services.GetRequiredService<TransipClient>();
        _previous = await GetInitialIPFromTransip(transip);
        _logger.LogInformation("Initial IP set to {IP}", _previous);
    }

    protected override async Task Run(CancellationToken stoppingToken)
    {
        using var serviceScope = _services.CreateScope();
        var services = serviceScope.ServiceProvider;

        var pushover = services.GetRequiredService<PushoverClient>();
        var transip = services.GetRequiredService<TransipClient>();
        
        var current = await GetMyCurrentPublicIP();
        _logger.LogDebug("Current IP is: {IP}", current);

        if (String.IsNullOrEmpty(current))
        {
            _logger.LogWarning("Failed to resolve current IP");
            return;
        }
        
        if (current.Equals(_previous)) return;

        _logger.LogInformation("IP changed from {PreviousIP} to {NewIP}, updating DNS records for {MyDomain} in Transip", _previous, current, Domain);

        var myDnsEntries = await transip.GetDnsEntries(Domain);
        var myOutdatedDnsEntries = myDnsEntries
            .Where(entry => entry.Content.Equals(_previous))
            .ToArray();
        
        // In case of failure, inform prior to performing individual updates, can screw ourselves over in case of a server reboot or w/e mid processing
        // maybe process A record with MyDomain name last?
        await pushover.SendMessage(PushoverMessage.Text(
            "Public IP changed",
            $"IP Changed from {_previous} to {current}\nUpdating the following DNS entries for {Domain}\n\n{String.Join("\n\n", myOutdatedDnsEntries.Select(x => $"name: {x.Name}\ntype: {x.Type}"))}"
        ));
        
        foreach (var dnsEntry in myOutdatedDnsEntries)
        {
            if (!dnsEntry.Content.Equals(_previous)) continue;
            
            _logger.LogInformation("Changing content for domain {MyDomain} DNS record with name {Name} and type {Type} to {NewIP}", Domain, dnsEntry.Name, dnsEntry.Type, current);
            dnsEntry.Content = current;
            await transip.UpdateDnsEntry(Domain, dnsEntry);
        }
        
        foreach (var traefikConfigUpdater in services.GetServices<TraefikConfigUpdater>()) await traefikConfigUpdater.Write(Domain, current);

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
        _logger.LogInformation("Attempting to resolve initial IP for {MyDomain}", Domain);
        
        // we're going to assume we have an A record for our domain matching our domain name
        var myDomainEntries = await transip.GetDnsEntries(Domain);
        return myDomainEntries
            .SingleOrDefault(e => 
                e.Type.Equals("A", StringComparison.OrdinalIgnoreCase) && 
                e.Name.Equals(Domain, StringComparison.OrdinalIgnoreCase)
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
