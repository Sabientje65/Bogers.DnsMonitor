using System.Net.Http.Json;

namespace Bogers.DnsMonitor.Traefik;

public class TraefikClient
{
    private readonly HttpClient _httpClient;
    
    public TraefikClient(IHttpClientFactory httpClientFactory)
    {
        _httpClient = httpClientFactory.CreateClient("traefik");
    }

    public async Task<Router[]> GetEnabledHttpRouters() => (await _httpClient.GetFromJsonAsync<Router[]>("/api/http/routers"))!
        .Where(x => x.Status.Equals("enabled"))
        .ToArray();
}

/// <summary>
/// A single traefik router
/// </summary>
public class Router
{
    /// <summary>
    /// Entrypoints utilized by rotuer
    /// </summary>
    public string[] EntryPoints { get; set; }
    
    /// <summary>
    /// Rule router listens to
    /// </summary>
    public string Rule { get; set; }
    
    /// <summary>
    /// Service name, used for deciding 'final' destination (forwarding, load balancing, etc)
    /// </summary>
    public string Service { get; set; }
    
    /// <summary>
    /// Router status, know values: enabled
    /// </summary>
    public string Status { get; set; }

    /// <summary>
    /// Router name
    /// </summary>
    public string Name { get; set; }
    
    /// <summary>
    /// Router provider (docker, file, etc.)
    /// </summary>
    public string Provider { get; set; }
}
