using System;
using System.IO;

namespace DARKSTAR.Core
{
    public static class Logger
    {
        private static string _logFilePath = "";
        private static readonly object _logLock = new object();
        private static bool _verboseLogging = false;
        private static bool _minimalMode = true;

        private static bool HasValidLogPath()
            => !string.IsNullOrWhiteSpace(_logFilePath);

        private static void SafeConsoleLogError(string message)
        {
            try
            {
                Console.WriteLine($"[LOG ERROR] {message}");
            }
            catch
            {
            }
        }

        public static bool VerboseLogging => _verboseLogging;
        public static bool MinimalMode => _minimalMode;

        public static void SetMinimalMode(bool minimal)
        {
            _minimalMode = minimal;
        }

        public static void Initialize()
        {
            try
            {
                string logFolder = "log";

                if (!Directory.Exists(logFolder))
                {
                    Directory.CreateDirectory(logFolder);
                }

                CleanupOldLogs(logFolder);

                string timestamp = DateTime.Now.ToString("yyyy-MM-dd-HH-mm-ss");
                _logFilePath = Path.Combine(logFolder, $"log-{timestamp}.gtxt");

                string header = $"DARKSTAR v1.0.0 Log - Started at {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n";
                header += "==========================================\n\n";

                File.WriteAllText(_logFilePath, header);
                WriteToFile($"Log file: {_logFilePath}");
            }
            catch (Exception ex)
            {
                SafeConsoleLogError(ex.Message);
            }
        }

        private static void CleanupOldLogs(string logFolder)
        {
            try
            {
                if (!Directory.Exists(logFolder))
                    return;

                var logFiles = Directory.GetFiles(logFolder, "log-*.gtxt")
                                       .Select(f => new FileInfo(f))
                                       .OrderByDescending(f => f.CreationTime)
                                       .ToList();

                if (logFiles.Count > 5)
                {
                    foreach (var file in logFiles.Skip(5))
                    {
                        try
                        {
                            file.Delete();
                            WriteToFile($"Removed old log file: {file.Name}");
                        }
                        catch (Exception ex)
                        {
                            WriteToFile($"Failed to remove old log {file.Name}: {ex.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                WriteToFile($"Error cleaning up old logs: {ex.Message}");
            }
        }

        private static void WriteToFile(string message)
        {
            lock (_logLock)
            {
                try
                {
                    if (!HasValidLogPath())
                        return;

                    string timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
                    string logEntry = $"[{timestamp}] {message}\n";
                    File.AppendAllText(_logFilePath, logEntry);
                }
                catch (Exception ex)
                {
                    SafeConsoleLogError(ex.Message);
                }
            }
        }

        public static void WriteColored(string text, ConsoleColor color, bool forceDisplay = false)
        {
            if (!_minimalMode || forceDisplay)
            {
                Console.ForegroundColor = color;
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {text}");
                Console.ResetColor();
            }
            WriteToFile(text);
        }

        public static void WriteMinimal(string text, ConsoleColor color = ConsoleColor.Cyan)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(text);
            Console.ResetColor();
            WriteToFile(text);
        }

        public static void WriteVerbose(string message, ConsoleColor color = ConsoleColor.Cyan)
        {
            WriteToFile($"VERBOSE: {message}");
            if (_verboseLogging)
            {
                Console.ForegroundColor = color;
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {message}");
                Console.ResetColor();
            }
        }

        public static void WriteLog(string message)
        {
            WriteToFile(message);
        }

        public static void ToggleVerbose()
        {
            _verboseLogging = !_verboseLogging;
            if (_verboseLogging)
            {
                WriteMinimal("🔍 VERBOSE LOGGING ON", ConsoleColor.Cyan);
            }
            else
            {
                WriteMinimal("🔍 VERBOSE LOGGING OFF", ConsoleColor.Cyan);
            }
        }

        public static string GetLogFilePath() => _logFilePath;
    }
}
