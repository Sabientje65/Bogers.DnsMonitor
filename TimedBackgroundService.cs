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
        for (var tries = 0; tries < 3; tries++)
        {
            try
            {
                await Initialize(stoppingToken);
                break;
            }
            catch (Exception e)
            {
                if (tries == 2)
                {
                    _logger.LogCritical(e, "Unhandled exception while attempting to initialize background service: {ServiceType}, failed to initialize after 3 tries, giving up...", GetType().FullName);
                    throw;
                }
                
                _logger.LogError(e, "Unhandled exception while attempting to initialize background service: {ServiceType}. Retrying...", GetType().FullName);
            }
        }
        
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

    protected virtual Task Initialize(CancellationToken stoppingToken) => Task.CompletedTask;

    // virtual Task Initialize()? -> no more keeping track of initial run
}