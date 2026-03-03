using System;
using System.Collections.Generic;

namespace DARKSTAR.Features
{
    public static class ScheduledTaskDisabler
    {
        private static bool _enabled = false;
        private static bool _tasksDisabled = false;
        private static readonly List<string> _disabledTasks = new List<string>();

        public static void Configure(bool enabled)
        {
            _enabled = enabled;
        }

        public static void DisableForGameSession()
        {
            if (!_enabled || _tasksDisabled)
                return;

            try
            {
                _tasksDisabled = true;
                Core.Logger.WriteVerbose("Scheduled tasks disabled (stub implementation)", ConsoleColor.Cyan);
            }
            catch (Exception ex)
            {
                Core.Logger.WriteLog($"Failed to disable scheduled tasks: {ex.Message}");
            }
        }

        public static void RestoreAfterGameSession()
        {
            if (!_enabled || !_tasksDisabled)
                return;

            try
            {
                _tasksDisabled = false;
                Core.Logger.WriteVerbose("Scheduled tasks restored (stub implementation)", ConsoleColor.Cyan);
            }
            catch (Exception ex)
            {
                Core.Logger.WriteLog($"Failed to restore scheduled tasks: {ex.Message}");
            }
        }
    }
}
