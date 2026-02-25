using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DARKSTAR.Features
{
    /// <summary>
    /// DWM thread-level optimizer for input latency reduction.
    ///
    /// DWM Thread Architecture (Windows 10 21H2+)
    /// ────────────────────────────────────────────
    /// DWM runs ~8-15 threads. Two are latency-critical for gaming:
    ///
    ///   CMit — "DWM Master Input Thread"
    ///     Handles input event routing through the compositor. Every mouse move,
    ///     click, and keyboard event that touches a DWM-composed surface goes
    ///     through CMit. This is the single most latency-sensitive thread in the
    ///     entire desktop composition pipeline.
    ///     → TIME_CRITICAL (15), P-cores, boost disabled (consistent scheduling)
    ///
    ///   CKst — "DWM Kernel Sensor Thread"
    ///     Handles composition timing signals, VSync coordination, and hardware
    ///     sensor feedback. This thread's responsiveness directly affects frame
    ///     presentation timing and input-to-photon latency. When CKst is delayed,
    ///     DWM presents frames late, adding compositor-side latency on top of
    ///     whatever the game's render pipeline produces.
    ///     → HIGHEST (2), P-cores, boost disabled
    ///
    ///   All other DWM threads (shader compilation, atlas management, telemetry,
    ///   diagnostic logging, DX runtime callbacks) are non-latency-critical.
    ///     → IDLE (-15), E-cores, boost disabled
    ///
    /// This is applied ONCE when a game is detected. Windows does not revert
    /// thread priorities. If DWM restarts (rare), the system process check at
    /// 60s intervals will re-detect it.
    /// </summary>
    public static class DwmOptimizer
    {
        #region P/Invoke

        [DllImport("kernel32.dll")]
        private static extern int GetThreadPriority(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr SetThreadAffinityMask(IntPtr hThread, IntPtr dwThreadAffinityMask);

        [DllImport("kernel32.dll")]
        private static extern bool SetThreadPriority(IntPtr hThread, int nPriority);

        [DllImport("kernel32.dll")]
        private static extern bool SetThreadPriorityBoost(IntPtr hThread, bool bDisablePriorityBoost);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int GetThreadDescription(IntPtr hThread, out IntPtr ppszThreadDescription);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr hMem);

        private const uint THREAD_QUERY_LIMITED_INFORMATION = 0x0800;
        private const uint THREAD_SET_INFORMATION = 0x0020;
        private const uint THREAD_QUERY_INFORMATION = 0x0040;

        #endregion

        // Thread name constants
        private const string THREAD_CMIT = "DWM Master Input Thread";
        private const string THREAD_CKST = "DWM Kernel Sensor Thread";

        /// <summary>
        /// Apply DWM thread optimizations ONCE when a game is detected.
        /// CMit + CKst → high priority on P-cores.
        /// Everything else → IDLE on E-cores.
        /// </summary>
        public static void ApplyOneTimeThreadOptimizations()
        {
            try
            {
                int criticalOptimized = 0;
                int demotedCount = 0;

                foreach (Process process in Process.GetProcessesByName("dwm"))
                {
                    try
                    {
                        if (process.HasExited) continue;

                        foreach (ProcessThread thread in process.Threads)
                        {
                            try
                            {
                                string threadName = GetThreadName(thread.Id);

                                if (threadName == THREAD_CMIT)
                                {
                                    // Master Input Thread → TIME_CRITICAL on P-cores
                                    ApplyThreadSettings(thread.Id, 15, "p-core", threadName);
                                    criticalOptimized++;
                                }
                                else if (threadName == THREAD_CKST)
                                {
                                    // Kernel Sensor Thread → HIGHEST on P-cores
                                    ApplyThreadSettings(thread.Id, 2, "p-core", threadName);
                                    criticalOptimized++;
                                }
                                else
                                {
                                    // All other DWM threads → IDLE on E-cores
                                    // This includes: shader compilation, atlas management,
                                    // telemetry, logging, DX callbacks, frame statistics.
                                    // None of these affect input-to-photon latency.
                                    ApplyThreadSettings(thread.Id, -15, "e-core", threadName);
                                    demotedCount++;
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }

                if (criticalOptimized > 0 || demotedCount > 0)
                {
                    Core.Logger.WriteVerbose(
                        $"[DWM] Thread optimization: {criticalOptimized} critical threads boosted, {demotedCount} background threads demoted",
                        ConsoleColor.Cyan);
                    Core.Logger.WriteLog(
                        $"[DWM] {criticalOptimized} critical + {demotedCount} demoted");
                }
                else
                {
                    Core.Logger.WriteVerbose("[DWM] No named DWM threads found (expected on some Windows versions)", ConsoleColor.DarkCyan);
                }
            }
            catch (Exception ex)
            {
                Core.Logger.WriteLog($"[DWM] Error: {ex.Message}");
            }
        }

        /// <summary>
        /// Apply priority, affinity, and boost settings to a single DWM thread.
        /// Tries user-mode first, falls back to kernel driver for PPL-protected threads.
        /// </summary>
        private static void ApplyThreadSettings(int threadId, int priority, string affinityStr, string threadName)
        {
            IntPtr threadHandle = OpenThread(
                THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, false, (uint)threadId);

            if (threadHandle != IntPtr.Zero)
            {
                try
                {
                    SetThreadPriority(threadHandle, priority);
                    SetThreadPriorityBoost(threadHandle, true);  // Disable boost for consistent scheduling

                    IntPtr affinity = Core.AffinityParser.Parse(affinityStr);
                    if (affinity != IntPtr.Zero)
                        SetThreadAffinityMask(threadHandle, affinity);

                    string label = FormatThreadLabel(threadName, threadId);
                    Core.Logger.WriteVerbose(
                        $"[DWM] {label} → prio {priority}, {affinityStr}", ConsoleColor.DarkCyan);
                }
                finally
                {
                    CloseHandle(threadHandle);
                }
            }
            else
            {
                // DWM is PPL-protected — use kernel driver
                if (Core.ConfigLoader.UseKernelDriver && Core.KernelDriverInterface.IsPplBypassAvailable)
                {
                    bool prioOk = Core.KernelDriverInterface.SetThreadPriority(threadId, priority);

                    IntPtr affinity = Core.AffinityParser.Parse(affinityStr);
                    bool affOk = affinity != IntPtr.Zero && Core.KernelDriverInterface.SetThreadAffinity(threadId, affinity);

                    if (prioOk || affOk)
                    {
                        string label = FormatThreadLabel(threadName, threadId);
                        Core.Logger.WriteVerbose(
                            $"[DWM] {label} → prio {priority}, {affinityStr} (kernel)", ConsoleColor.DarkCyan);
                    }
                }
            }
        }

        private static string FormatThreadLabel(string threadName, int threadId)
        {
            if (threadName == "NO_NAME" || threadName == "EMPTY" || threadName == "NO_ACCESS")
                return $"TID {threadId}";
            return $"{threadName} (TID {threadId})";
        }

        private static string GetThreadName(int threadId)
        {
            IntPtr threadHandle = IntPtr.Zero;
            IntPtr namePtr = IntPtr.Zero;
            try
            {
                threadHandle = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, (uint)threadId);
                if (threadHandle == IntPtr.Zero)
                    return "NO_ACCESS";

                int result = GetThreadDescription(threadHandle, out namePtr);
                if (result >= 0 && namePtr != IntPtr.Zero)
                {
                    string? name = Marshal.PtrToStringUni(namePtr);
                    return string.IsNullOrEmpty(name) ? "EMPTY" : name!;
                }

                return "NO_NAME";
            }
            finally
            {
                if (namePtr != IntPtr.Zero)
                    LocalFree(namePtr);
                if (threadHandle != IntPtr.Zero)
                    CloseHandle(threadHandle);
            }
        }
    }
}
