namespace Bogers.DnsMonitor;

/// <summary>
/// Main worker, single entrypoint for performing monitoring on DNS records
/// </summary>
public class MainWorker : BackgroundService
{
    private readonly ILogger<MainWorker> _logger;

    public MainWorker(ILogger<MainWorker> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            if (_logger.IsEnabled(LogLevel.Information))
            {
                _logger.LogInformation("Worker running at: {time}", DateTimeOffset.Now);
            }

            await Task.Delay(1000, stoppingToken);
        }
    }
}

// public record RecordChangesEvent(string Value, string )
// {
//     
//     
// }
