namespace Bogers.DnsMonitor;

/// <summary>
/// Baseclass providing scheduling for background services running on an interval
/// </summary>
public abstract class TimedBackgroundService : BackgroundService
{
    private readonly ILogger _logger;

    protected TimedBackgroundService(ILogger logger) => _logger = logger;

    protected abstract TimeSpan Interval { get; }
    
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // autostart first run
        try
        {
            await Run(stoppingToken);
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Unhandled exception while running background service: {ServiceType}", GetType().FullName);
        }
        
        // then schedule periodically
        using var timer = new PeriodicTimer(Interval);
        
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await Run(stoppingToken);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Unhandled exception while running background service: {ServiceType}", GetType().FullName);
            }
        }
    }

    protected abstract Task Run(CancellationToken stoppingToken);
}