using Bogers.DnsMonitor.Dns;

namespace Bogers.DnsMonitor.Monitoring;

/// <summary>
/// Monitor the IP address for an external domain, update whitelists etc. when updated
/// </summary>
public class ExternalDomainIPMonitorService : TimedBackgroundService
{
    private readonly ILogger _logger;
    private readonly IServiceProvider _services;

    /// <summary>
    /// Domain to monitor for associated IP changes
    /// </summary>
    public required string Domain { get; init; }

    public ExternalDomainIPMonitorService(ILogger<ExternalDomainIPMonitorService> logger, IServiceProvider services) : base(logger)
    {
        _logger = logger;
        _services = services;
    }

    protected override TimeSpan Interval => TimeSpan.FromMinutes(1);
    protected override async Task Run(CancellationToken stoppingToken)
    {
        using var serviceScope = _services.CreateScope();
        var services = serviceScope.ServiceProvider;

        var dnsResolver = services.GetRequiredService<DnsResolver>();
        var domainIP = await ResolveDomainIP(dnsResolver, TimeSpan.FromSeconds(30));
        if (String.IsNullOrEmpty(domainIP)) return;
        
        _logger.LogDebug("IP for {Domain} is {IP}", Domain, domainIP);

        foreach (var traefikConfigUpdater in services.GetServices<TraefikConfigUpdater>()) await traefikConfigUpdater.Write(Domain, domainIP);
    }

    private async Task<string?> ResolveDomainIP(DnsResolver resolver, TimeSpan timeout)
    {
        try
        {
            using var cls = new CancellationTokenSource(timeout);
            return await resolver.ResolveIPV4(Domain, cls.Token);
        }
        catch(TaskCanceledException)
        {
            _logger.LogWarning("Timed out after {Seconds} while resolving IPV4 for {Domain}", timeout.TotalSeconds, Domain);
            return null;
        }

    }
}