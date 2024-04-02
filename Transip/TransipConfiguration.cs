namespace Bogers.DnsMonitor.Transip;

public class TransipConfiguration
{
    /// <summary>
    /// Path pointing to transip private key, used to request access tokens
    /// </summary>
    public string PrivateKeyPath { get; set; }
    
    /// <summary>
    /// Transip username
    /// </summary>
    public string Username { get; set; }
}