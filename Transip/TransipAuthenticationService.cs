﻿using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;

namespace Bogers.DnsMonitor.Transip;

/// <summary>
/// Service managing transip authentication, revalidation, etc.
/// </summary>
public class TransipAuthenticationService
{
    private readonly ILogger<TransipAuthenticationService> _logger;
    
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly TransipConfiguration _configuration;

    private readonly SemaphoreSlim _sema = new SemaphoreSlim(1, 1);
    
    /// <summary>
    /// Transip allows 1 token/label, generate a unique suffix to bypass this when deemed necessary
    /// </summary>
    private string _labelSuffix = DateTime.UtcNow.ToString("hhmmss");

    /// <summary>
    /// Current access token used for authorizing requests
    /// </summary>
    private AccessToken _currentToken = AccessToken.Expired;

    public TransipAuthenticationService(
        ILogger<TransipAuthenticationService> logger,
        IHttpClientFactory httpClientFactory,
        IOptions<TransipConfiguration> configuration
    )
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _configuration = configuration.Value;
    }
    
    // public HttpClient GetAuthenticatedClient() // <-- Should we create an API like this?

    /// <summary>
    /// Creates an authenticated message for use with the transip API
    /// </summary>
    /// <param name="forceRefresh">When true, will forcefully request a new access token</param>
    /// <returns>Authenticated message</returns>
    public async Task<HttpRequestMessage> CreateMessage(bool forceRefresh = false) => await Authenticate(new HttpRequestMessage(), forceRefresh);
    
    /// <summary>
    /// Authenticates the given message for use with the transip API
    /// </summary>
    /// <param name="msg">Message to authenticate</param>
    /// <param name="forceRefresh">When true, will forcefully request a new access token</param>
    public async Task<HttpRequestMessage> Authenticate(HttpRequestMessage msg, bool forceRefresh = false)
    {
        if (forceRefresh)
        {
            _logger.LogInformation("Forcefully discarding previous transip access token, current suffix: {LabelSuffix}", _labelSuffix);
            
            // attempt to remove previous header
            msg.Headers.Remove("Authorization");
        }
        
        if (!forceRefresh && !_currentToken.IsExpired)
        {
            _logger.LogDebug("Authenticating request with transip access token, current suffix: {LabelSuffix}", _labelSuffix);
            
            msg.Headers.Add("Authorization", $"Bearer {_currentToken.Value}");
            return msg;
        }

        var previousTokenId = _currentToken.Id;
        await _sema.WaitAsync();

        try
        {
            if (previousTokenId != _currentToken.Id)
            {
                _logger.LogInformation("Token already updated, skipping refresh, current suffix: {LabelSuffix}", _labelSuffix);
                _logger.LogDebug("Authenticating request with transip access token, current suffix: {LabelSuffix}", _labelSuffix);
            
                msg.Headers.Add("Authorization", $"Bearer {_currentToken.Value}");
                return msg;
            }
            
            _labelSuffix = DateTime.UtcNow.ToString("hhmmss");
            _logger.LogInformation("Attempting to retrieve new transip access token, current suffix: {LabelSuffix}", _labelSuffix);
            
            using var client = _httpClientFactory.CreateClient("transip");
        
            // only 1 active token/label allowed!
            var body = JsonSerializer.Serialize(new
            {
                login = _configuration.Username,
                nonce = Guid.NewGuid().ToString("N"),
                read_only = false,
                expiration_time = "30 minutes",
                label = $"Bogers.DnsMonitor:{_labelSuffix}",
                global_key = true
            });

            // https://gathering.tweakers.net/forum/list_messages/2201582
            var bodyBytes = Encoding.UTF8.GetBytes(body);
            var pemChars = Encoding.UTF8.GetChars(await File.ReadAllBytesAsync(_configuration.PrivateKeyPath));
            using var rsa = new RSACryptoServiceProvider();
            rsa.ImportFromPem(pemChars);
            var signature = rsa.SignData(bodyBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
            var signatureBase64 = Convert.ToBase64String(signature);

            using var request = new HttpRequestMessage(HttpMethod.Post, "/v6/auth");
            request.Headers.Add("Signature", signatureBase64);
            request.Content = new ByteArrayContent(bodyBytes);
            request.Headers.TryAddWithoutValidation("Content-Type", "application/json");

            var response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();
            
            var responseBody = await response.Content.ReadFromJsonAsync<JsonNode>();
            var jwt = responseBody!["token"]!.GetValue<string>();

            // https://stackoverflow.com/a/49085706
            var payload = jwt.Split('.')[1]
                .Replace('_', '/')
                .Replace('-', '+');
            
            // base64 encoded, pad to a length dividable by 4 to ensure we can decode it
            if (payload.Length % 4 != 0)
            {
                var padding = 4 - (payload.Length % 4);
                payload += new string('=', padding);   
            }

            var expiresTimestamp = JsonNode.Parse(Convert.FromBase64String(payload))["exp"].GetValue<int>();
            var expiresDate = DateTime.UnixEpoch.AddSeconds(expiresTimestamp);

            _currentToken = new AccessToken(jwt, expiresDate);
            
            _logger.LogInformation("Authenticating request with new transip token, current suffix: {LabelSuffix}", _labelSuffix);
            msg.Headers.Add("Authorization", $"Bearer {_currentToken.Value}");
            
            return msg;   
        } 
        finally
        {
            _sema.Release();
        }
    }
    
    private class AccessToken
    {
        private DateTime _expireDate;
        
        public AccessToken(string value, DateTime expireDate)
        {
            _expireDate = expireDate;
            Value = value;
        }

        public static readonly AccessToken Expired = new AccessToken(String.Empty, DateTime.UtcNow);

        /// <summary>
        /// Identifier for the current token, used to re-validate whether a refresh is necessary when multiple refreshes are requested concurrently
        /// </summary>
        public readonly Guid Id = Guid.NewGuid();
        
        /// <summary>
        /// Expire the current token
        /// </summary>
        /// <returns></returns>
        public AccessToken Expire()
        {
            _expireDate = DateTime.UtcNow;
            return this;
        }
        
        /// <summary>
        /// JWT token
        /// </summary>
        public string Value { get; }

        /// <summary>
        /// Check if the token is still usable, returns
        /// </summary>
        public bool IsExpired => _expireDate < DateTime.UtcNow;
    }
    
}