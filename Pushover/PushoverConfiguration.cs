namespace Bogers.DnsMonitor.Pushover;

public class PushoverConfiguration
{
    public string AppToken { get; set; }
    public string UserToken { get; set; }
    public bool Enabled { get; set; } = true;
}