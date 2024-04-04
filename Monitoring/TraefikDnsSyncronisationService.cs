using System.Text.RegularExpressions;
using Bogers.DnsMonitor.Pushover;
using Bogers.DnsMonitor.Traefik;
using Bogers.DnsMonitor.Transip;

namespace Bogers.DnsMonitor.Monitoring;

/// <summary>
/// Automatically create/wipe DNS records for traefik managed services
/// </summary>
public class TraefikDnsSynchronisationService : TimedBackgroundService
{
    private readonly ILogger _logger;
    private readonly IServiceProvider _services;
    private DnsEntry[] _transipDnsEntries = Array.Empty<DnsEntry>();
    
    // constantly poll for new services being created :-)
    protected override TimeSpan Interval => TimeSpan.FromSeconds(5);

    public required string Domain { get; init; }
    

    private readonly Regex SimpleHostRuleExp = new Regex(@"^Host\(`(.+)`\)$");
    
    
    public TraefikDnsSynchronisationService(
        ILogger<TraefikDnsSynchronisationService> logger, 
        IServiceProvider services
    ) : base(logger)
    {
        _logger = logger;
        _services = services;
    }

    protected override async Task Initialize(CancellationToken stoppingToken)
    {
        using var serviceScope = _services.CreateScope();
        var services = serviceScope.ServiceProvider;
        
        _logger.LogInformation("Initializing traefik DNS sync for {Domain}", Domain);

        var transip = services.GetRequiredService<TransipClient>();
        _transipDnsEntries = await transip.GetDnsEntries(Domain);
    }

    protected override async Task Run(CancellationToken stoppingToken)
    {
        using var serviceScope = _services.CreateScope();
        var services = serviceScope.ServiceProvider;

        var transip = services.GetRequiredService<TransipClient>();
        var pushover = services.GetRequiredService<PushoverClient>();
        var traefik = services.GetRequiredService<TraefikClient>();

        var enabledHosts = await GetAllEnabledHostsForConfiguredDomain(traefik);
        _logger.LogDebug("Found {HostCount} enabled hosts for domain {Domain} in traefik", Domain, enabledHosts.Length);
        
        var currentCnames = _transipDnsEntries
            .Where(entry => entry.Type.Equals("CNAME", StringComparison.OrdinalIgnoreCase))
            .Select(x => x.Name)
            .ToArray();
        
        _logger.LogDebug("Found {HostCount} CNAME records for {Domain} in transip", currentCnames.Length, Domain);
        
        var newHosts = enabledHosts
            .Select(h => h.Replace($".{Domain}", String.Empty, StringComparison.OrdinalIgnoreCase))
            .Except(currentCnames, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        
        var createdEntries = new List<DnsEntry>();
        
        _logger.LogDebug("Detected {HostCount} new hosts added in traefik", newHosts.Length);

        foreach (var newHost in newHosts)
        {
            try
            {
                var ttl = (int)TimeSpan.FromMinutes(60).TotalSeconds;
                _logger.LogInformation("Attempting to create CNAME record for host {Host}, pointing to {Domain}, with a TTL of {Ttl} seconds", newHost, Domain, ttl);
                
                var entry = new DnsEntry
                {
                    Name = newHost,
                    Type = "CNAME",
                    Content = Domain,
                    Expire = ttl
                };
                
                await transip.CreateDnsEntry(Domain, entry);
                createdEntries.Add(entry);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Failed to create CNAME record pointing to {Domain}, for newly detected host: {Host}", Domain, newHost);
            }
        }

        if (!createdEntries.Any()) return;
        
        _logger.LogInformation("Created {HostCount} new CNAME records", createdEntries.Count);
        
        _transipDnsEntries = await transip.GetDnsEntries(Domain);
        await pushover.SendMessage(PushoverMessage.Text(
            "New DNS entries created", 
            $"Created the following DNS entries for {Domain}:\n\n{String.Join("\n\n", createdEntries.Select(e => $"name: {e.Name}\ntype: {e.Type}\ncontent: {e.Content}"))}"
        ));
    }
    
    private async Task<string[]> GetAllEnabledHostsForConfiguredDomain(TraefikClient traefik) => (await traefik.GetEnabledHttpRouters())
        .Select(x => x.Rule)
        .Where(x => SimpleHostRuleExp.IsMatch(x))
        .Select(x => SimpleHostRuleExp.Replace(x, "$1"))
        .Where(x => x.EndsWith(Domain, StringComparison.OrdinalIgnoreCase))
        .ToArray();
    
}