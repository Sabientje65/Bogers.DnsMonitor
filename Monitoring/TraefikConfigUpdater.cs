using System.Text.RegularExpressions;

namespace Bogers.DnsMonitor.Monitoring;

/// <summary>
/// Service for updating traefik configuration files, ensuring the current ip associated with the given domain is used
///
/// Assumes any included ip is followed by a `#dnsmonitor:example.com` marker comment where `example.com` is the domain to monitor
/// </summary>
public class TraefikConfigUpdater
{
    private readonly ILogger<TraefikConfigUpdater> _logger;
    
    public required string Path { get; init; }
    
    // $1 -> start (cant include digits for now)
    // $2 -> ip address
    // $3 -> padding etc.
    // $4 -> domain
    private readonly Regex _matcherExp = new Regex(@"(\D+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s*#dnsmonitor\:)(.+)$", RegexOptions.Compiled | RegexOptions.Singleline);
    
    public TraefikConfigUpdater(ILogger<TraefikConfigUpdater> logger) => _logger = logger;

    /// <summary>
    /// Update all ip addresses associated with the given domain in the configured traefik config file
    /// </summary>
    /// <param name="domain">Domain name</param>
    /// <param name="ip">Current IP address</param>
    public async Task Write(string domain, string ip)
    {
        if (!File.Exists(Path))
        {
            _logger.LogWarning("No file found at path {Path}", Path);
            return;
        }

        var lines = await File.ReadAllLinesAsync(Path);
        var didChange = false;
        
        for (var idx = 0; idx < lines.Length; idx++)
        {
            var line = lines[idx];
            if (!_matcherExp.IsMatch(line)) continue;

            var matchedDomain = _matcherExp.Replace(line, "$4");
            if (!matchedDomain.Equals(domain, StringComparison.OrdinalIgnoreCase)) continue;

            lines[idx] = _matcherExp.Replace(lines[idx], $"$1 {ip}$3$4");
            didChange = didChange || line != lines[idx];
        }

        if (didChange)
        {
            _logger.LogInformation("Updated {Domain} to {IP} in {Path}", domain, ip, Path);
            await File.WriteAllLinesAsync(Path, lines);
        }
    }
}