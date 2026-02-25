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
    /// Priority:  REALTIME (base priority 24) — preempts all non-realtime threads.
    ///            This ensures input messages are dispatched with the absolute minimum
    ///            scheduler latency. csrss threads are short-burst by nature (handle
    ///            an input event, return) so REALTIME won't cause sustained starvation.
    ///
    /// I/O:       CRITICAL (4) — csrss rarely does disk I/O, but when it does (console
    ///            logging, subsystem init) it should never be queued behind background
    ///            I/O from browsers, indexers, or telemetry.
    ///
    /// Page:      5 (maximum) — csrss pages should never be evicted to the standby list
    ///            during memory pressure. A page fault in the input path adds 1-10ms
    ///            of latency per event.
    ///
    /// dwm.exe (process-level)
    /// ───────────────────────
    /// Desktop compositor. DWM thread-level tuning is handled separately in DwmOptimizer
    /// (CMit/CKst kept high, everything else demoted). At the process level we set
    /// BELOW_NORMAL so DWM's non-critical threads yield to the game without starving
    /// the compositor entirely (which would cause swap chain presentation stalls).
    ///
    /// I/O:       LOW (1) — DWM's shader cache and surface readback are low-priority.
    /// Page:      LOW (2) — DWM surfaces are GPU-resident; its CPU-side pages are less
    ///            critical than csrss or the game.
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
            // csrss.exe → REALTIME + CRITICAL I/O + max Page priority
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

                        // REALTIME priority class
                        if (SetPriorityClass(hProcess, REALTIME_PRIORITY_CLASS))
                        {
                            Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) → REALTIME", ConsoleColor.Green);
                        }

                        // CRITICAL I/O priority
                        int ioPriority = IoPriorityCritical;
                        int status = NtSetInformationProcess(hProcess, ProcessIoPriority, ref ioPriority, sizeof(int));
                        if (status == 0)
                        {
                            Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) I/O → CRITICAL", ConsoleColor.Green);
                        }
                        else
                        {
                            // CRITICAL may be rejected in user-mode — try HIGH as fallback
                            ioPriority = IoPriorityHigh;
                            NtSetInformationProcess(hProcess, ProcessIoPriority, ref ioPriority, sizeof(int));
                            Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) I/O → HIGH (CRITICAL rejected user-mode)", ConsoleColor.DarkCyan);
                        }

                        // Maximum page priority
                        int pagePriority = PagePriorityNormal;
                        status = NtSetInformationProcess(hProcess, ProcessPagePriority, ref pagePriority, sizeof(int));
                        if (status == 0)
                        {
                            Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) Page → 5 (max)", ConsoleColor.Green);
                        }

                        Core.Logger.WriteLog($"[SYS-OPT] csrss (PID {pid}): REALTIME, I/O CRITICAL, Page MAX");
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

            // REALTIME via kernel driver (NT priority class 4)
            if (Core.KernelDriverInterface.SetProcessPriorityDarkstar((uint)pid, NT_PRIORITY_REALTIME))
            {
                Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) → REALTIME via kernel", ConsoleColor.Green);
            }
            else
            {
                Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) REALTIME FAILED via kernel", ConsoleColor.Red);
            }

            // CRITICAL I/O via kernel driver — bypasses user-mode restriction on level 4
            if (Core.KernelDriverInterface.SetProcessIoPriority((uint)pid, IoPriorityCritical))
            {
                Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) I/O → CRITICAL via kernel", ConsoleColor.Green);
            }
            else
            {
                Core.Logger.WriteVerbose($"[SYS-OPT] csrss (PID {pid}) I/O CRITICAL FAILED", ConsoleColor.Yellow);
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

            Core.Logger.WriteLog($"[SYS-OPT] csrss (PID {pid}): REALTIME, I/O CRITICAL, Page MAX (kernel driver)");
        }

        #endregion

        #region DWM Process-Level Optimization

        private static void OptimizeDwm()
        {
            // dwm.exe → BELOW_NORMAL + LOW I/O + LOW Page (process-level)
            // Thread-level tuning (CMit/CKst high, rest demoted) is in DwmOptimizer.
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
                        if (Core.ConfigLoader.UseKernelDriver && Core.KernelDriverInterface.IsPplBypassAvailable)
                        {
                            ApplyDwmViaKernelDriver(pid);
                        }
                        continue;
                    }

                    try
                    {
                        SaveOriginalState(hProcess, pid, "dwm");

                        if (SetPriorityClass(hProcess, BELOW_NORMAL_PRIORITY_CLASS))
                        {
                            Core.Logger.WriteVerbose($"[SYS-OPT] dwm (PID {pid}) → BELOW_NORMAL", ConsoleColor.Green);
                        }

                        int ioPriority = IoPriorityLow;
                        int status = NtSetInformationProcess(hProcess, ProcessIoPriority, ref ioPriority, sizeof(int));
                        if (status == 0)
                        {
                            Core.Logger.WriteVerbose($"[SYS-OPT] dwm (PID {pid}) I/O → LOW", ConsoleColor.DarkCyan);
                        }

                        int pagePriority = PagePriorityLow;
                        status = NtSetInformationProcess(hProcess, ProcessPagePriority, ref pagePriority, sizeof(int));
                        if (status == 0)
                        {
                            Core.Logger.WriteVerbose($"[SYS-OPT] dwm (PID {pid}) Page → LOW", ConsoleColor.DarkCyan);
                        }

                        Core.Logger.WriteLog($"[SYS-OPT] dwm (PID {pid}): BELOW_NORMAL, I/O LOW, Page LOW");
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
            Core.Logger.WriteVerbose($"[SYS-OPT] dwm (PID {pid}) via kernel driver", ConsoleColor.Cyan);

            SaveOriginalStateDefault(pid, "dwm");

            if (Core.KernelDriverInterface.SetProcessPriorityDarkstar((uint)pid, NT_PRIORITY_BELOW_NORMAL))
            {
                Core.Logger.WriteVerbose($"[SYS-OPT] dwm (PID {pid}) → BELOW_NORMAL via kernel", ConsoleColor.Green);
            }

            if (Core.KernelDriverInterface.SetProcessIoPriority((uint)pid, IoPriorityLow))
            {
                Core.Logger.WriteVerbose($"[SYS-OPT] dwm (PID {pid}) I/O → LOW via kernel", ConsoleColor.Green);
            }

            if (Core.KernelDriverInterface.SetProcessPagePriority((uint)pid, PagePriorityLow))
            {
                Core.Logger.WriteVerbose($"[SYS-OPT] dwm (PID {pid}) Page → LOW via kernel", ConsoleColor.Green);
            }

            Core.Logger.WriteLog($"[SYS-OPT] dwm (PID {pid}): BELOW_NORMAL, I/O LOW, Page LOW (kernel driver)");
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
