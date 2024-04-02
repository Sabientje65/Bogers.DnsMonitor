using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bogers.DnsMonitor.Pushover;
using Microsoft.Extensions.Options;

namespace Bogers.DnsMonitor.Transip;

/// <summary>
/// Service for communicating with transip api
/// </summary>
public class TransipClient
{
    private readonly ILogger _logger;

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly TransipConfiguration _transipConfiguration;

    private AccessToken? _currentToken = new AccessToken();
    
    public TransipClient(
        ILogger<TransipClient> logger,
        IHttpClientFactory httpClientFactory, 
        IOptions<TransipConfiguration> configuration
    )
    {
        _logger = logger;
        _httpClientFactory = httpClientFactory;
        _transipConfiguration = configuration.Value;
        
        
        
        // _client = httpClientFactory.CreateClient("transip");
        // _client.BaseAddress = new Uri("https://api.transip.nl/v6");
    }

    public async Task Send()
    {
        using var client = await CreateClient();
    }
    
    // /// <summary>
    // /// Send a notification via pushover
    // /// </summary>
    // /// <param name="message">Message to send</param>
    // public async Task SendMessage(PushoverMessage message)
    // {
    //     // log message? trace invocation?
    //     // if (!_transipConfiguration.Enabled) return;
    //     //
    //     // var payload = JsonSerializer.SerializeToNode(message);
    //     // _logger.LogDebug("Sending message: {Payload}", payload);
    //     //
    //     // payload["token"] = _transipConfiguration.AppToken;
    //     // payload["user"] = _transipConfiguration.UserToken;
    //     //
    //     // // todo: logging + error handling
    //     // try
    //     // {
    //     //     ThrowIfConfigurationInvalid();
    //     //     using var res = await _client.PostAsJsonAsync("/1/messages.json", payload);
    //     //     res.EnsureSuccessStatusCode();
    //     // }
    //     // catch (Exception e)
    //     // {
    //     //     _logger.LogWarning(e, "Failed to send pushover message");
    //     // }
    // }

    private void ThrowIfConfigurationInvalid()
    {
        if (String.IsNullOrEmpty(_transipConfiguration.PrivateKeyPath))
        {
            throw new Exception("Invalid pushover configuration! Missing either AppToken, or UserToken");
        }
    }

    private async Task<HttpClient> CreateClient()
    {
        var client = _httpClientFactory.CreateClient("transip");
        // client.BaseAddress = new Uri("https://api.transip.nl/v6");
        var currentToken = _currentToken;

        await GenerateAccessToken();
        
        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {currentToken.Value}");

        return client;

        async Task<AccessToken> GenerateAccessToken()
        {
            var body = JsonSerializer.Serialize(new
            {
                login = _transipConfiguration.Username,
                nonce = Guid.NewGuid().ToString("N"),
                read_only = false,
                expiration_time = "30 minutes",
                label = "Bogers.DnsMonitor",
                global_key = true
            });

            // https://gathering.tweakers.net/forum/list_messages/2201582
            var bodyBytes = Encoding.UTF8.GetBytes(body);
            // var body2Bytes = Encoding.UTF8.GetBytes(body2);
            var pemChars = Encoding.UTF8.GetChars(await File.ReadAllBytesAsync(_transipConfiguration.PrivateKeyPath));
            using var rsa = new RSACryptoServiceProvider();
            rsa.ImportFromPem(pemChars);
            var signature = rsa.SignData(bodyBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
            var signatureBase64 = Convert.ToBase64String(signature);

            using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.transip.nl/v6/auth");
            // client.DefaultRequestHeaders.Clear();
            request.Headers.Add("Signature", signatureBase64);
            request.Content = new ByteArrayContent(bodyBytes);
            request.Headers.TryAddWithoutValidation("Content-Type", "application/json");

            var response = await client.SendAsync(request);
            var responseBody = await response.Content.ReadFromJsonAsync<JsonNode>();

            return new AccessToken();

            // var pk = File.ReadAllText(_transipConfiguration.PrivateKeyPath);

            // rsa.ImportFromPem(Encoding.UTF8.GetChars(pemChars));
            //
            // rsa.SignData("abc")

        }
    }

    class AccessToken
    {
        public string Value { get; set; }
        
        public bool IsUsable { get; }
    }
    
}
