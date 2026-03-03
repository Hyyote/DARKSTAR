using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DARKSTAR.Features
{
    public enum GpuPriority
    {
        None = 0,
        VeryLow = 1,
        Low = 2,
        Normal = 3,
        High = 4
    }

    public static class GpuPriorityManager
    {
        #region P/Invoke Declarations

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtSetInformationProcess(
            IntPtr ProcessHandle,
            PROCESS_INFORMATION_CLASS ProcessInformationClass,
            ref PROCESS_POWER_THROTTLING_STATE ProcessInformation,
            int ProcessInformationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint PROCESS_SET_INFORMATION = 0x0200;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        private enum PROCESS_INFORMATION_CLASS
        {
            ProcessPowerThrottling = 76
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_POWER_THROTTLING_STATE
        {
            public uint Version;
            public uint ControlMask;
            public uint StateMask;
        }

        private const uint PROCESS_POWER_THROTTLING_EXECUTION_SPEED = 0x1;
        private const uint PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION = 0x4;
        private const uint PROCESS_POWER_THROTTLING_CURRENT_VERSION = 1;

        #endregion

        private static readonly Dictionary<int, (GpuPriority Priority, DateTime LastApplied)>
            _appliedGpuPriorities = new Dictionary<int, (GpuPriority, DateTime)>();

        private static readonly object _lock = new object();

        public static bool SetGpuPriority(Process process, GpuPriority priority)
        {
            if (process == null || process.HasExited)
                return false;

            if (priority == GpuPriority.None)
            {
                lock (_lock)
                {
                    _appliedGpuPriorities.Remove(process.Id);
                }
                return true;
            }

            IntPtr processHandle = IntPtr.Zero;
            try
            {
                processHandle = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)process.Id);
                if (processHandle == IntPtr.Zero)
                {
                    Core.Logger.WriteLog($"Failed to open process {process.ProcessName} (PID {process.Id}) for GPU priority: Access denied");
                    return false;
                }

                var throttlingState = new PROCESS_POWER_THROTTLING_STATE
                {
                    Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION,
                    ControlMask = 0,
                    StateMask = 0
                };

                switch (priority)
                {
                    case GpuPriority.VeryLow:
                        throttlingState.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED | PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION;
                        throttlingState.StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED | PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION;
                        break;

                    case GpuPriority.Low:
                        throttlingState.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
                        throttlingState.StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
                        break;

                    case GpuPriority.Normal:
                        throttlingState.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED | PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION;
                        throttlingState.StateMask = 0;
                        break;

                    case GpuPriority.High:
                        throttlingState.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED | PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION;
                        throttlingState.StateMask = 0;
                        break;
                }

                int result = NtSetInformationProcess(
                    processHandle,
                    PROCESS_INFORMATION_CLASS.ProcessPowerThrottling,
                    ref throttlingState,
                    Marshal.SizeOf<PROCESS_POWER_THROTTLING_STATE>());

                if (result == 0)
                {
                    lock (_lock)
                    {
                        _appliedGpuPriorities[process.Id] = (priority, DateTime.Now);
                    }
                    Core.Logger.WriteVerbose($"GPU priority set to {priority} for {process.ProcessName} (PID {process.Id})", ConsoleColor.DarkCyan);
                    Core.Logger.WriteLog($"GPU priority set to {priority} for {process.ProcessName} (PID {process.Id})");
                    return true;
                }
                else
                {
                    Core.Logger.WriteLog($"Failed to set GPU priority for {process.ProcessName} (PID {process.Id}): NtStatus = 0x{result:X8}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Core.Logger.WriteLog($"Exception setting GPU priority for {process.ProcessName}: {ex.Message}");
                return false;
            }
            finally
            {
                if (processHandle != IntPtr.Zero)
                    CloseHandle(processHandle);
            }
        }

        public static bool SetGpuPriority(int processId, GpuPriority priority)
        {
            try
            {
                var process = Process.GetProcessById(processId);
                return SetGpuPriority(process, priority);
            }
            catch (ArgumentException)
            {
                lock (_lock)
                {
                    _appliedGpuPriorities.Remove(processId);
                }
                return false;
            }
        }

        public static void ReapplyGpuPriorities()
        {
            List<int> processesToCheck;
            lock (_lock)
            {
                processesToCheck = new List<int>(_appliedGpuPriorities.Keys);
            }

            foreach (var processId in processesToCheck)
            {
                try
                {
                    var process = Process.GetProcessById(processId);
                    if (process.HasExited)
                    {
                        lock (_lock)
                        {
                            _appliedGpuPriorities.Remove(processId);
                        }
                        continue;
                    }

                    lock (_lock)
                    {
                        if (_appliedGpuPriorities.TryGetValue(processId, out var info))
                        {
                            SetGpuPriority(process, info.Priority);
                        }
                    }
                }
                catch (ArgumentException)
                {
                    lock (_lock)
                    {
                        _appliedGpuPriorities.Remove(processId);
                    }
                }
                catch (Exception ex)
                {
                    Core.Logger.WriteLog($"Error reapplying GPU priority for PID {processId}: {ex.Message}");
                }
            }
        }

        public static void RemoveTracking(int processId)
        {
            lock (_lock)
            {
                _appliedGpuPriorities.Remove(processId);
            }
        }

        public static void ClearTracking()
        {
            lock (_lock)
            {
                _appliedGpuPriorities.Clear();
            }
        }

        public static GpuPriority ParseGpuPriority(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return GpuPriority.None;

            return value.Trim().ToLowerInvariant() switch
            {
                "very_low" or "verylow" or "very low" => GpuPriority.VeryLow,
                "low" => GpuPriority.Low,
                "normal" => GpuPriority.Normal,
                "high" => GpuPriority.High,
                "none" or "" => GpuPriority.None,
                _ => GpuPriority.None
            };
        }

        public static string GpuPriorityToString(GpuPriority priority)
        {
            return priority switch
            {
                GpuPriority.VeryLow => "very_low",
                GpuPriority.Low => "low",
                GpuPriority.Normal => "normal",
                GpuPriority.High => "high",
                _ => "none"
            };
        }
    }
}
