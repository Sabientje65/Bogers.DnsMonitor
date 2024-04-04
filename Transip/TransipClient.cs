using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Bogers.DnsMonitor.Transip;

/// <summary>
/// Service for communicating with transip api
/// </summary>
public class TransipClient : IDisposable
{
    private readonly ILogger _logger;

    private readonly HttpClient _httpClient;
    private readonly TransipAuthenticationService _authenticationService;
    
    private static readonly JsonSerializerOptions _transipJsonSerializerOptions = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };
    
    public TransipClient(ILogger<TransipClient> logger, IHttpClientFactory httpClientFactory, TransipAuthenticationService authenticationService)
    {
        _logger = logger;
        _authenticationService = authenticationService;
        _httpClient = httpClientFactory.CreateClient("transip");
    }

    /// <summary>
    /// Attempt to update the given DNS entry
    /// </summary>
    /// <param name="domain">Domain the entry belongs to</param>
    /// <param name="entry">Updated entry</param>
    public async Task UpdateDnsEntry(string domain, DnsEntry entry)
    {
        using var _ = await Send($"/v6/domains/{domain}/dns", msg =>
        {
            var entryJson = new JsonObject
            {
                { "dnsEntry", JsonSerializer.SerializeToNode(entry, _transipJsonSerializerOptions) }
            }.ToString();
            
            msg.Method = HttpMethod.Patch;
            msg.Content = new StringContent(entryJson, Encoding.UTF8, "application/json");
        });
    }
    
    /// <summary>
    /// Create a DNS entry in TransIP for the given domain
    /// </summary>
    /// <param name="domain">Domain to create entry for</param>
    /// <param name="entry">Entry to create</param>
    public async Task CreateDnsEntry(string domain, DnsEntry entry)
    {
        using var response = await Send($"/v6/domains/{domain}/dns", msg =>
        {
            var entryJson = new JsonObject
            {
                { "dnsEntry", JsonSerializer.SerializeToNode(entry, _transipJsonSerializerOptions) }
            }.ToString();

            msg.Method = HttpMethod.Post;
            msg.Content = new StringContent(entryJson);
        });
    }


    /// <summary>
    /// Get all entries for the given domain
    /// </summary>
    /// <param name="domain">Domain to get entries for</param>
    /// <returns>Array of entries</returns>
    public async Task<DnsEntry[]> GetDnsEntries(string domain)
    {
        using var response = await Send($"/v6/domains/{domain}/dns");
        var responseJson = await response.Content.ReadFromJsonAsync<JsonNode>();

        return responseJson["dnsEntries"]
            .AsArray()
            .Deserialize<DnsEntry[]>(_transipJsonSerializerOptions);
    }
    
    /// <summary>
    /// Send an authenticated request to the given Uri, will retry once in case of authentication failure
    /// </summary>
    /// <param name="uri">Uri of the endpoint to send request to</param>
    /// <param name="configureMessage">Optional configurator for adding a payload, headers, etc.</param>
    /// <returns>Response</returns>
    private async Task<HttpResponseMessage> Send(
        [StringSyntax(StringSyntaxAttribute.Uri)] string uri,
        Action<HttpRequestMessage>? configureMessage = null
    )
    {
        // noop, just send a request to the given url
        configureMessage ??= _ => { };
        
        using var msg = await _authenticationService.CreateMessage();
        msg.RequestUri = new Uri(uri, UriKind.RelativeOrAbsolute);
        
        configureMessage(msg);
            
        var res = await _httpClient.SendAsync(msg);
        if (res.IsSuccessStatusCode) return res;

        if (res.StatusCode != HttpStatusCode.Unauthorized)
        {
            res.EnsureSuccessStatusCode();
            res.Dispose();
        }
        
        // assume we just became unauthorized, try again
        using var msg2 = await _authenticationService.CreateMessage(true);
        msg2.RequestUri = new Uri(uri, UriKind.RelativeOrAbsolute);
        
        configureMessage(msg2);
        
        res = await _httpClient.SendAsync(msg2);
        res.EnsureSuccessStatusCode();
        return res;
    }
    
    public void Dispose() => _httpClient.Dispose();
}

/// <summary>
/// Single DNS entry in TransIP format
/// </summary>
public class DnsEntry
{
    /// <summary>
    /// Entry name
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// Entry typename
    /// </summary>
    public required string Type { get; init; }
    
    /// <summary>
    /// Entry TTL
    /// </summary>
    public required int Expire { get; set; }

    /// <summary>
    /// Entry data
    /// </summary>
    public required string Content { get; set; }
}
