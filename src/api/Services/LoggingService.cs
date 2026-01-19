using Serilog;

namespace Skills.Services
{
    public interface ILoggingService
    {
        void LogInfo(string message, object? data = null);
        void LogWarning(string message, object? data = null);
        void LogError(string message, Exception? exception = null, object? data = null);
        void LogDebug(string message, object? data = null);
    }

    public class LoggingService : ILoggingService
    {
        private readonly Serilog.ILogger _logger;

        public LoggingService(Serilog.ILogger logger)
        {
            _logger = logger;
        }

        public void LogInfo(string message, object? data = null)
        {
            if (data != null)
                _logger.Information(message + " {@Data}", data);
            else
                _logger.Information(message);
        }

        public void LogWarning(string message, object? data = null)
        {
            if (data != null)
                _logger.Warning(message + " {@Data}", data);
            else
                _logger.Warning(message);
        }

        public void LogError(string message, Exception? exception = null, object? data = null)
        {
            if (exception != null && data != null)
                _logger.Error(exception, message + " {@Data}", data);
            else if (exception != null)
                _logger.Error(exception, message);
            else if (data != null)
                _logger.Error(message + " {@Data}", data);
            else
                _logger.Error(message);
        }

        public void LogDebug(string message, object? data = null)
        {
            if (data != null)
                _logger.Debug(message + " {@Data}", data);
            else
                _logger.Debug(message);
        }
    }
}
