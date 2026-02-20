using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace DARKSTAR.Features
{
    public static class BackgroundProcessCloser
    {
        private static bool _enabled = false;
        private static bool _active = false;
        private static readonly HashSet<string> _targetProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public static void Configure(bool enabled, IEnumerable<string> processNames)
        {
            _enabled = enabled;
            _targetProcesses.Clear();
            if (_enabled && processNames != null)
            {
                foreach (var name in processNames)
                {
                    var trimmed = name?.Trim();
                    if (!string.IsNullOrEmpty(trimmed))
                        _targetProcesses.Add(trimmed.Replace(".exe", string.Empty, StringComparison.OrdinalIgnoreCase));
                }
            }
        }

        public static void CloseForGameSession()
        {
            if (!_enabled || _active || _targetProcesses.Count == 0)
                return;

            try
            {
                foreach (var procName in _targetProcesses)
                {
                    try
                    {
                        var procs = Process.GetProcessesByName(procName);
                        foreach (var proc in procs)
                        {
                            proc.CloseMainWindow();
                            if (!proc.WaitForExit(2000))
                            {
                                proc.Kill();
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Core.Logger.WriteLog($"Failed to close {procName}: {ex.Message}");
                    }
                }
                _active = true;
                Core.Logger.WriteVerbose("Background processes closed for gaming session", ConsoleColor.Cyan);
            }
            catch (Exception ex)
            {
                Core.Logger.WriteLog($"Failed to close background processes: {ex.Message}");
            }
        }

        public static void RestoreAfterGameSession()
        {
            if (!_enabled || !_active)
                return;

            try
            {
                _active = false;
                Core.Logger.WriteVerbose("Background process closing restored", ConsoleColor.Cyan);
            }
            catch (Exception ex)
            {
                Core.Logger.WriteLog($"Failed to restore background processes: {ex.Message}");
            }
        }
    }
}
