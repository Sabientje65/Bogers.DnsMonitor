using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;

namespace Bogers.DnsMonitor.Pushover;

/// <summary>
/// Service for sending notifications via pushover
/// </summary>
public class PushoverClient : IDisposable
{
    private readonly ILogger _logger;
    
    private readonly HttpClient _client;
    private readonly PushoverConfiguration _pushoverConfiguration;
    
    private static readonly JsonSerializerOptions _pushoverJsonSerializerOptions = new JsonSerializerOptions()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };
    
    public PushoverClient(
        ILogger<PushoverClient> logger,
        IHttpClientFactory httpClientFactory, 
        IOptions<PushoverConfiguration> configuration
    )
    {
        _logger = logger;
        _client = httpClientFactory.CreateClient("pushover");
        _pushoverConfiguration = configuration.Value;
        
        _client.BaseAddress = new Uri("https://api.pushover.net");
    }

    /// <summary>
    /// Send a notification via pushover
    /// </summary>
    /// <param name="message">Message to send</param>
    public async Task SendMessage(PushoverMessage message)
    {
        // log message? trace invocation?
        if (!_pushoverConfiguration.Enabled) return;
        
        var payload = JsonSerializer.SerializeToNode(message, _pushoverJsonSerializerOptions);
        _logger.LogDebug("Sending message: {Payload}", payload);
        
        payload["token"] = _pushoverConfiguration.AppToken;
        payload["user"] = _pushoverConfiguration.UserToken;
        
        // todo: logging + error handling
        try
        {
            ThrowIfConfigurationInvalid();
            using var res = await _client.PostAsJsonAsync("/1/messages.json", payload);
            res.EnsureSuccessStatusCode();
        }
        catch (Exception e)
        {
            _logger.LogWarning(e, "Failed to send pushover message");
        }
    }

    private void ThrowIfConfigurationInvalid()
    {
        if (
            String.IsNullOrEmpty(_pushoverConfiguration.AppToken) ||
            String.IsNullOrEmpty(_pushoverConfiguration.UserToken)
        )
        {
            throw new Exception("Invalid pushover configuration! Missing either AppToken, or UserToken");
        }
    }

    public void Dispose()
    {
        _client.Dispose();
    }
}