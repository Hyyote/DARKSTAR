using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DARKSTAR.Features
{
    /// <summary>
    /// Optimizes critical system processes (csrss, dwm) for minimum input latency.
    ///
    /// csrss.exe
    /// ─────────
    /// Handles the Win32 subsystem: raw input dispatch, Win32k user-mode callbacks,
    /// console I/O, and process/thread creation notifications. Every mouse/keyboard
    /// event passes through csrss before reaching the game's message pump.
    ///
    /// Priority:  HIGH (base priority 13) — preempts normal/above-normal threads.
    ///            REALTIME (24) is NOT used because csrss is PPL-protected and
    ///            setting REALTIME from user-mode can cause priority inversions
    ///            with kernel threads, leading to STATUS_UNKNOWN_HARD_ERROR.
    ///            HIGH is sufficient — csrss threads are short-burst.
    ///
    /// I/O:       HIGH (3) — csrss rarely does disk I/O, but when it does it should
    ///            not be queued behind background I/O. CRITICAL (4) is NOT used
    ///            because it is reserved for kernel memory manager paging I/O.
    ///
    /// Page:      5 (maximum) — csrss pages should never be evicted to the standby list
    ///            during memory pressure. A page fault in the input path adds 1-10ms
    ///            of latency per event.
    ///
    /// dwm.exe (process-level)
    /// ───────────────────────
    /// Desktop compositor. DWM thread-level tuning is handled separately in DwmOptimizer
    /// (CMit/CKst kept high, everything else demoted). At the process level we keep
    /// NORMAL so DWM's compositor threads are not starved. Demoting DWM to BELOW_NORMAL
    /// causes swap chain presentation stalls and can trigger desktop compositor crashes
    /// (STATUS_UNKNOWN_HARD_ERROR). The thread-level tuning in DwmOptimizer handles
    /// the prioritization of critical vs non-critical DWM threads.
    ///
    /// I/O:       NORMAL (2) — keep DWM I/O responsive for surface management.
    /// Page:      NORMAL (5) — DWM surfaces need to stay resident for smooth compositing.
    /// </summary>
    public static class SystemProcessOptimizer
    {
        #region P/Invoke

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

        private const uint PROCESS_SET_INFORMATION = 0x0200;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        // Win32 priority classes
        private const uint REALTIME_PRIORITY_CLASS = 0x00000100;
        private const uint HIGH_PRIORITY_CLASS = 0x00000080;
        private const uint ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000;
        private const uint NORMAL_PRIORITY_CLASS = 0x00000020;
        private const uint BELOW_NORMAL_PRIORITY_CLASS = 0x00004000;
        private const uint IDLE_PRIORITY_CLASS = 0x00000040;

        // NtSetInformationProcess information classes
        private const int ProcessIoPriority = 33;
        private const int ProcessPagePriority = 39;

        // I/O priority levels (IoePriorityHint)
        private const int IoPriorityVeryLow = 0;
        private const int IoPriorityLow = 1;
        private const int IoPriorityNormal = 2;
        private const int IoPriorityHigh = 3;
        private const int IoPriorityCritical = 4;   // Reserved for MM paging I/O — kernel driver bypasses restriction

        // Page priority levels (MEMORY_PRIORITY_INFORMATION)
        private const int PagePriorityLowest = 0;
        private const int PagePriorityVeryLow = 1;
        private const int PagePriorityLow = 2;
        private const int PagePriorityMedium = 3;
        private const int PagePriorityBelowNormal = 4;
        private const int PagePriorityNormal = 5;    // Maximum — pages are never demoted from active list

        // NT process priority class values (for kernel driver)
        private const byte NT_PRIORITY_IDLE = 1;
        private const byte NT_PRIORITY_NORMAL = 2;
        private const byte NT_PRIORITY_HIGH = 3;
        private const byte NT_PRIORITY_REALTIME = 4;
        private const byte NT_PRIORITY_BELOW_NORMAL = 5;
        private const byte NT_PRIORITY_ABOVE_NORMAL = 6;

        #endregion

        #region State

        private static bool _isOptimized = false;
        private static readonly object _lock = new object();

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

        #region Public API

        /// <summary>
        /// Apply gaming optimizations to csrss and dwm. Called ONCE when a game is detected.
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

                Core.Logger.WriteMinimal("Applying system process optimizations...", ConsoleColor.Cyan);

                OptimizeCsrss();
                OptimizeDwm();

                _isOptimized = true;
                Core.Logger.WriteMinimal("System process optimizations applied", ConsoleColor.Green);
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
                    return;

                Core.Logger.WriteMinimal("Restoring system process priorities...", ConsoleColor.Cyan);

                foreach (var kvp in _originalStates)
                {
                    int pid = kvp.Key;
                    var state = kvp.Value;

                    try
                    {
                        var process = Process.GetProcessById(pid);
                        if (process.HasExited) continue;

                        IntPtr hProcess = OpenProcess(
                            PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION,
                            false, (uint)pid);

                        if (hProcess != IntPtr.Zero)
                        {
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
                        else if (Core.ConfigLoader.UseKernelDriver && Core.KernelDriverInterface.IsPplBypassAvailable)
                        {
                            Core.KernelDriverInterface.SetProcessPriorityDarkstar((uint)pid, NT_PRIORITY_NORMAL);
                            Core.KernelDriverInterface.SetProcessIoPriority((uint)pid, IoPriorityNormal);
                            Core.KernelDriverInterface.SetProcessPagePriority((uint)pid, PagePriorityNormal);

                            Core.Logger.WriteVerbose($"[SYS-OPT] Restored {state.ProcessName} (PID {pid}) via kernel driver", ConsoleColor.DarkCyan);
                        }
                    }
                    catch (Exception ex)
                    {
                        Core.Logger.WriteLog($"[SYS-OPT] Failed to restore {state.ProcessName}: {ex.Message}");
                    }
                }

                _originalStates.Clear();
                _isOptimized = false;
                Core.Logger.WriteMinimal("System process priorities restored", ConsoleColor.Green);
            }
        }

        #endregion

        #region csrss Optimization

        private static void OptimizeCsrss()
        {
            // csrss.exe → HIGH + HIGH I/O + max Page priority
            // HIGH (not REALTIME) avoids priority inversions with kernel threads.
            // HIGH I/O (not CRITICAL) avoids using the kernel-reserved paging I/O level.
            foreach (var process in Process.GetProcessesByName("csrss"))
            {
                try
                {
                    int pid = process.Id;

                    // csrss is PPL-protected — OpenProcess will almost always fail.
                    // Go straight to kernel driver if available, fall back to user-mode attempt.
                    IntPtr hProcess = OpenProcess(
                        PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
                        false, (uint)pid);

                    if (hProcess == IntPtr.Zero)
                    {
                        if (Core.ConfigLoader.UseKernelDriver && Core.KernelDriverInterface.IsPplBypassAvailable)
                        {
                            ApplyCsrssViaKernelDriver(pid);
                        }
                        else
                        {
                            Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) is PPL-protected and no kernel driver available", ConsoleColor.Yellow);
                        }
                        continue;
                    }

                    try
                    {
                        SaveOriginalState(hProcess, pid, "csrss");

                        // HIGH priority class (not REALTIME — avoids scheduler inversions)
                        if (SetPriorityClass(hProcess, HIGH_PRIORITY_CLASS))
                        {
                            Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) → HIGH", ConsoleColor.Green);
                        }

                        // HIGH I/O priority (not CRITICAL — CRITICAL is kernel-reserved)
                        int ioPriority = IoPriorityHigh;
                        int status = NtSetInformationProcess(hProcess, ProcessIoPriority, ref ioPriority, sizeof(int));
                        if (status == 0)
                        {
                            Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) I/O → HIGH", ConsoleColor.Green);
                        }

                        // Maximum page priority
                        int pagePriority = PagePriorityNormal;
                        status = NtSetInformationProcess(hProcess, ProcessPagePriority, ref pagePriority, sizeof(int));
                        if (status == 0)
                        {
                            Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) Page → 5 (max)", ConsoleColor.Green);
                        }

                        Core.Logger.WriteLog($"[SYS-OPT] csrss (PID {pid}): HIGH, I/O HIGH, Page MAX");
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

        private static void ApplyCsrssViaKernelDriver(int pid)
        {
            Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) via kernel driver", ConsoleColor.Cyan);

            SaveOriginalStateDefault(pid, "csrss");

            // HIGH via kernel driver (NT priority class 3) — not REALTIME to avoid inversions
            if (Core.KernelDriverInterface.SetProcessPriorityDarkstar((uint)pid, NT_PRIORITY_HIGH))
            {
                Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) → HIGH via kernel", ConsoleColor.Green);
            }
            else
            {
                Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) HIGH FAILED via kernel", ConsoleColor.Red);
            }

            // HIGH I/O via kernel driver (not CRITICAL — reserved for MM paging)
            if (Core.KernelDriverInterface.SetProcessIoPriority((uint)pid, IoPriorityHigh))
            {
                Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) I/O → HIGH via kernel", ConsoleColor.Green);
            }
            else
            {
                Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) I/O HIGH FAILED", ConsoleColor.Yellow);
            }

            // Maximum page priority via kernel driver
            if (Core.KernelDriverInterface.SetProcessPagePriority((uint)pid, PagePriorityNormal))
            {
                Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) Page → 5 (max) via kernel", ConsoleColor.Green);
            }
            else
            {
                Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) Page MAX FAILED", ConsoleColor.Yellow);
            }

            Core.Logger.WriteLog($"[SYS-OPT] csrss (PID {pid}): HIGH, I/O HIGH, Page MAX (kernel driver)");
        }

        #endregion

        #region DWM Process-Level Optimization

        private static void OptimizeDwm()
        {
            // dwm.exe → keep NORMAL priority (thread-level tuning in DwmOptimizer handles differentiation)
            // Setting DWM to BELOW_NORMAL starves the compositor and causes presentation stalls.
            // I/O and Page kept at NORMAL to avoid compositor hitching.
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
                        // DWM is PPL-protected — skip process-level changes, let DwmOptimizer
                        // handle thread-level tuning via kernel driver if available.
                        Core.Logger.WriteVerbose($"[SYS-OPT] dwm (PID {pid}) PPL-protected, skipping process-level (thread-level via DwmOptimizer)", ConsoleColor.DarkCyan);
                        continue;
                    }

                    try
                    {
                        SaveOriginalState(hProcess, pid, "dwm");

                        // Keep DWM at NORMAL — thread-level tuning handles the rest
                        // Just ensure page priority is high so compositor surfaces stay resident
                        int pagePriority = PagePriorityNormal;
                        int status = NtSetInformationProcess(hProcess, ProcessPagePriority, ref pagePriority, sizeof(int));
                        if (status == 0)
                        {
                            Core.Logger.WriteVerbose($"[SYS-OPT] dwm (PID {pid}) Page → NORMAL (max)", ConsoleColor.DarkCyan);
                        }

                        Core.Logger.WriteLog($"[SYS-OPT] dwm (PID {pid}): NORMAL (process-level), Page NORMAL");
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

        private static void ApplyDwmViaKernelDriver(int pid)
        {
            // No-op: DWM process-level priority is kept at NORMAL.
            // Thread-level tuning is handled by DwmOptimizer.
            Core.Logger.WriteVerbose($"[SYS-OPT] dwm (PID {pid}) process-level skipped (thread-level via DwmOptimizer)", ConsoleColor.DarkCyan);
            SaveOriginalStateDefault(pid, "dwm");
        }

        #endregion

        #region State Helpers

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

            int ioPrio = 0;
            if (NtQueryInformationProcess(hProcess, ProcessIoPriority, ref ioPrio, sizeof(int), out _) == 0)
                state.IoPriority = ioPrio;

            int pagePrio = 0;
            if (NtQueryInformationProcess(hProcess, ProcessPagePriority, ref pagePrio, sizeof(int), out _) == 0)
                state.PagePriority = pagePrio;

            _originalStates[pid] = state;
            Core.Logger.WriteVerbose($"[SYS-OPT] Saved state: {processName} (PID {pid}) Class={state.PriorityClass} IO={state.IoPriority} Page={state.PagePriority}", ConsoleColor.DarkGray);
        }

        private static void SaveOriginalStateDefault(int pid, string processName)
        {
            if (_originalStates.ContainsKey(pid))
                return;

            // Can't query PPL-protected process — assume defaults
            _originalStates[pid] = new ProcessPriorityState
            {
                ProcessName = processName,
                PriorityClass = NORMAL_PRIORITY_CLASS,
                IoPriority = IoPriorityNormal,
                PagePriority = PagePriorityNormal
            };
        }

        #endregion
    }
}
