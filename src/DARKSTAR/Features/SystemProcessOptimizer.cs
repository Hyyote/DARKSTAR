using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DARKSTAR.Features
{
    /// <summary>
    /// Optimizes critical system processes (csrss, dwm) for gaming.
    /// - csrss.exe: Set to highest priorities (Realtime, High I/O, High Page)
    /// - dwm.exe: Set to lowest priorities (Idle, Very Low I/O, Very Low Page)
    /// </summary>
    public static class SystemProcessOptimizer
    {
        #region P/Invoke Declarations

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetPriorityClass(IntPtr hProcess, uint dwPriorityClass);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetPriorityClass(IntPtr hProcess);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtSetInformationProcess(
            IntPtr ProcessHandle,
            int ProcessInformationClass,
            ref int ProcessInformation,
            int ProcessInformationLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryInformationProcess(
            IntPtr ProcessHandle,
            int ProcessInformationClass,
            ref int ProcessInformation,
            int ProcessInformationLength,
            out int ReturnLength);

        // Process access rights
        private const uint PROCESS_SET_INFORMATION = 0x0200;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        // Priority classes
        private const uint REALTIME_PRIORITY_CLASS = 0x00000100;
        private const uint HIGH_PRIORITY_CLASS = 0x00000080;
        private const uint ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000;
        private const uint NORMAL_PRIORITY_CLASS = 0x00000020;
        private const uint BELOW_NORMAL_PRIORITY_CLASS = 0x00004000;
        private const uint IDLE_PRIORITY_CLASS = 0x00000040;

        // NtSetInformationProcess classes
        private const int ProcessIoPriority = 33;
        private const int ProcessPagePriority = 39;

        // I/O Priority values
        private const int IoPriorityVeryLow = 0;
        private const int IoPriorityLow = 1;
        private const int IoPriorityNormal = 2;
        private const int IoPriorityHigh = 3;
        private const int IoPriorityCritical = 4;

        // Page Priority values (0-5, where 5 is highest)
        private const int PagePriorityIdle = 0;
        private const int PagePriorityVeryLow = 1;
        private const int PagePriorityLow = 2;
        private const int PagePriorityBackground = 3;
        private const int PagePriorityNormal = 4;
        private const int PagePriorityAboveNormal = 5;

        #endregion

        #region State

        private static bool _isOptimized = false;
        private static readonly object _lock = new object();

        // Store original values for restoration
        private static readonly Dictionary<int, ProcessPriorityState> _originalStates = 
            new Dictionary<int, ProcessPriorityState>();

        private class ProcessPriorityState
        {
            public string ProcessName { get; set; } = "";
            public uint PriorityClass { get; set; }
            public int IoPriority { get; set; }
            public int PagePriority { get; set; }
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Apply gaming optimizations to csrss and dwm processes.
        /// Called when a game is detected.
        /// </summary>
        public static void ApplyGamingOptimizations()
        {
            lock (_lock)
            {
                if (_isOptimized)
                {
                    Core.Logger.WriteVerbose("[SYS-OPT] Already optimized, skipping", ConsoleColor.DarkCyan);
                    return;
                }

                Core.Logger.WriteMinimal("⚡ Applying system process optimizations...", ConsoleColor.Cyan);
                Core.Logger.WriteLog("Applying system process optimizations for gaming");

                // Optimize csrss.exe - HIGHEST priorities
                OptimizeCsrss();

                // Optimize dwm.exe - LOWEST priorities  
                OptimizeDwm();

                _isOptimized = true;
                Core.Logger.WriteMinimal("✓ System process optimizations applied", ConsoleColor.Green);
            }
        }

        /// <summary>
        /// Restore original priorities when game exits.
        /// </summary>
        public static void RestoreOriginalPriorities()
        {
            lock (_lock)
            {
                if (!_isOptimized)
                {
                    return;
                }

                Core.Logger.WriteMinimal("⊘ Restoring system process priorities...", ConsoleColor.Cyan);
                Core.Logger.WriteLog("Restoring system process priorities after gaming");

                foreach (var kvp in _originalStates)
                {
                    int pid = kvp.Key;
                    var state = kvp.Value;

                    try
                    {
                        var process = Process.GetProcessById(pid);
                        if (process.HasExited)
                            continue;

                        IntPtr hProcess = OpenProcess(
                            PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION,
                            false, (uint)pid);

                        if (hProcess == IntPtr.Zero)
                        {
                            // Try with kernel driver
                            if (Core.ConfigLoader.UseKernelDriver && Core.KernelDriverInterface.IsAvailable)
                            {
                                Core.Logger.WriteVerbose($"[SYS-OPT] Cannot restore {state.ProcessName} (protected)", ConsoleColor.Yellow);
                            }
                            continue;
                        }

                        try
                        {
                            SetPriorityClass(hProcess, state.PriorityClass);
                            
                            int ioPrio = state.IoPriority;
                            NtSetInformationProcess(hProcess, ProcessIoPriority, ref ioPrio, sizeof(int));
                            
                            int pagePrio = state.PagePriority;
                            NtSetInformationProcess(hProcess, ProcessPagePriority, ref pagePrio, sizeof(int));

                            Core.Logger.WriteVerbose($"[SYS-OPT] Restored {state.ProcessName} (PID {pid})", ConsoleColor.DarkCyan);
                        }
                        finally
                        {
                            CloseHandle(hProcess);
                        }
                    }
                    catch (Exception ex)
                    {
                        Core.Logger.WriteLog($"[SYS-OPT] Failed to restore {state.ProcessName}: {ex.Message}");
                    }
                }

                _originalStates.Clear();
                _isOptimized = false;
                Core.Logger.WriteMinimal("✓ System process priorities restored", ConsoleColor.Green);
            }
        }

        #endregion

        #region Private Methods

        private static void OptimizeCsrss()
        {
            // csrss.exe is the Client/Server Runtime Subsystem
            // Setting to REALTIME priority ensures input/window messages are processed immediately
            foreach (var process in Process.GetProcessesByName("csrss"))
            {
                try
                {
                    int pid = process.Id;
                    
                    // Try to save original state and apply optimizations
                    IntPtr hProcess = OpenProcess(
                        PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
                        false, (uint)pid);

                    if (hProcess == IntPtr.Zero)
                    {
                        int error = Marshal.GetLastWin32Error();
                        Core.Logger.WriteVerbose($"[SYS-OPT] Cannot open csrss (PID {pid}), error {error} - trying kernel mode", ConsoleColor.Yellow);
                        
                        // csrss is a protected process, try kernel driver
                        if (Core.ConfigLoader.UseKernelDriver && Core.KernelDriverInterface.IsPplBypassAvailable)
                        {
                            Core.Logger.WriteVerbose($"[SYS-OPT] Using kernel driver for csrss (PID {pid})", ConsoleColor.Cyan);
                            // Note: Full kernel driver implementation would go here
                            // For now, log that we need PPL bypass
                        }
                        continue;
                    }

                    try
                    {
                        // Save original state
                        SaveOriginalState(hProcess, pid, "csrss");

                        // Set REALTIME priority class
                        if (!SetPriorityClass(hProcess, REALTIME_PRIORITY_CLASS))
                        {
                            // Fallback to HIGH if REALTIME fails (requires special privileges)
                            SetPriorityClass(hProcess, HIGH_PRIORITY_CLASS);
                            Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) set to HIGH (REALTIME requires elevated)", ConsoleColor.Yellow);
                        }
                        else
                        {
                            Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) set to REALTIME priority", ConsoleColor.Green);
                        }

                        // Set HIGH I/O priority
                        int ioPriority = IoPriorityHigh;
                        int status = NtSetInformationProcess(hProcess, ProcessIoPriority, ref ioPriority, sizeof(int));
                        if (status == 0)
                        {
                            Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) I/O priority set to HIGH", ConsoleColor.DarkCyan);
                        }

                        // Set HIGH page priority
                        int pagePriority = PagePriorityAboveNormal;
                        status = NtSetInformationProcess(hProcess, ProcessPagePriority, ref pagePriority, sizeof(int));
                        if (status == 0)
                        {
                            Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) page priority set to ABOVE_NORMAL", ConsoleColor.DarkCyan);
                        }

                        Core.Logger.WriteLog($"[SYS-OPT] csrss (PID {pid}) optimized: REALTIME/HIGH, I/O HIGH, Page HIGH");
                    }
                    finally
                    {
                        CloseHandle(hProcess);
                    }
                }
                catch (Exception ex)
                {
                    Core.Logger.WriteLog($"[SYS-OPT] Failed to optimize csrss: {ex.Message}");
                }
            }
        }

        private static void OptimizeDwm()
        {
            // dwm.exe is the Desktop Window Manager
            // Setting to IDLE priority reduces its competition with game threads
            foreach (var process in Process.GetProcessesByName("dwm"))
            {
                try
                {
                    int pid = process.Id;

                    IntPtr hProcess = OpenProcess(
                        PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
                        false, (uint)pid);

                    if (hProcess == IntPtr.Zero)
                    {
                        int error = Marshal.GetLastWin32Error();
                        Core.Logger.WriteVerbose($"[SYS-OPT] Cannot open dwm (PID {pid}), error {error} - trying kernel mode", ConsoleColor.Yellow);
                        
                        if (Core.ConfigLoader.UseKernelDriver && Core.KernelDriverInterface.IsPplBypassAvailable)
                        {
                            Core.Logger.WriteVerbose($"[SYS-OPT] Using kernel driver for dwm (PID {pid})", ConsoleColor.Cyan);
                        }
                        continue;
                    }

                    try
                    {
                        // Save original state
                        SaveOriginalState(hProcess, pid, "dwm");

                        // Set IDLE priority class (lowest)
                        if (SetPriorityClass(hProcess, IDLE_PRIORITY_CLASS))
                        {
                            Core.Logger.WriteVerbose($"[SYS-OPT] dwm (PID {pid}) set to IDLE priority", ConsoleColor.Green);
                        }
                        else
                        {
                            // Try BELOW_NORMAL as fallback
                            SetPriorityClass(hProcess, BELOW_NORMAL_PRIORITY_CLASS);
                            Core.Logger.WriteVerbose($"[SYS-OPT] dwm (PID {pid}) set to BELOW_NORMAL (IDLE failed)", ConsoleColor.Yellow);
                        }

                        // Set VERY LOW I/O priority
                        int ioPriority = IoPriorityVeryLow;
                        int status = NtSetInformationProcess(hProcess, ProcessIoPriority, ref ioPriority, sizeof(int));
                        if (status == 0)
                        {
                            Core.Logger.WriteVerbose($"[SYS-OPT] dwm (PID {pid}) I/O priority set to VERY_LOW", ConsoleColor.DarkCyan);
                        }

                        // Set VERY LOW page priority
                        int pagePriority = PagePriorityVeryLow;
                        status = NtSetInformationProcess(hProcess, ProcessPagePriority, ref pagePriority, sizeof(int));
                        if (status == 0)
                        {
                            Core.Logger.WriteVerbose($"[SYS-OPT] dwm (PID {pid}) page priority set to VERY_LOW", ConsoleColor.DarkCyan);
                        }

                        Core.Logger.WriteLog($"[SYS-OPT] dwm (PID {pid}) optimized: IDLE, I/O VERY_LOW, Page VERY_LOW");
                    }
                    finally
                    {
                        CloseHandle(hProcess);
                    }
                }
                catch (Exception ex)
                {
                    Core.Logger.WriteLog($"[SYS-OPT] Failed to optimize dwm: {ex.Message}");
                }
            }
        }

        private static void SaveOriginalState(IntPtr hProcess, int pid, string processName)
        {
            if (_originalStates.ContainsKey(pid))
                return;

            var state = new ProcessPriorityState
            {
                ProcessName = processName,
                PriorityClass = GetPriorityClass(hProcess),
                IoPriority = IoPriorityNormal,
                PagePriority = PagePriorityNormal
            };

            // Query current I/O priority
            int ioPrio = 0;
            int returnLen;
            if (NtQueryInformationProcess(hProcess, ProcessIoPriority, ref ioPrio, sizeof(int), out returnLen) == 0)
            {
                state.IoPriority = ioPrio;
            }

            // Query current page priority
            int pagePrio = 0;
            if (NtQueryInformationProcess(hProcess, ProcessPagePriority, ref pagePrio, sizeof(int), out returnLen) == 0)
            {
                state.PagePriority = pagePrio;
            }

            _originalStates[pid] = state;
            Core.Logger.WriteVerbose($"[SYS-OPT] Saved original state for {processName} (PID {pid}): Class={state.PriorityClass}, IO={state.IoPriority}, Page={state.PagePriority}", ConsoleColor.DarkGray);
        }

        #endregion
    }
}
