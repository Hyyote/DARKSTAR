using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace DARKSTAR.Core
{
    /// <summary>
    /// Intelligent game thread detector with behavioral analysis.
    /// Combines name-based pattern matching with runtime metrics (CPU usage,
    /// wake intervals, cycle counts) to classify threads and assign optimal
    /// priority/affinity settings.
    /// </summary>
    public static class IntelligentThreadDetector
    {
        #region P/Invoke Declarations

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        private static extern int GetThreadPriority(IntPtr hThread);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        private static extern int GetThreadDescription(IntPtr hThread, out IntPtr ppszThreadDescription);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationThread(
            IntPtr ThreadHandle,
            int ThreadInformationClass,
            ref IntPtr ThreadInformation,
            uint ThreadInformationLength,
            out uint ReturnLength);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationThread(
            IntPtr ThreadHandle,
            int ThreadInformationClass,
            ref THREAD_CYCLE_TIME_INFORMATION ThreadInformation,
            uint ThreadInformationLength,
            out uint ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetThreadTimes(
            IntPtr hThread,
            out long lpCreationTime,
            out long lpExitTime,
            out long lpKernelTime,
            out long lpUserTime);

        [DllImport("kernel32.dll")]
        private static extern void GetSystemTimes(
            out long lpIdleTime,
            out long lpKernelTime,
            out long lpUserTime);

        [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
        private static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, StringBuilder lpFilename, uint nSize);

        [DllImport("psapi.dll")]
        private static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded, uint dwFilterFlag);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [StructLayout(LayoutKind.Sequential)]
        private struct THREAD_CYCLE_TIME_INFORMATION
        {
            public ulong AccumulatedCycles;
            public ulong CurrentCycleCount;
        }

        private const uint THREAD_QUERY_INFORMATION = 0x0040;
        private const uint THREAD_QUERY_LIMITED_INFORMATION = 0x0800;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;
        private const int ThreadQuerySetWin32StartAddress = 9;
        private const int ThreadCycleTime = 17;

        #endregion

        #region Thread Name Patterns

        private static readonly string[] MainThreadPatterns = new[]
        {
            "main", "gamethread", "game_thread", "mainthread", "main_thread",
            "primarythread", "primary_thread", "gameloop", "game_loop"
        };

        private static readonly string[] RenderThreadPatterns = new[]
        {
            "render", "gpu", "dx11", "dx12", "d3d", "vulkan", "opengl",
            "renderthread", "render_thread", "graphicsthread", "graphics_thread",
            "drawthread", "draw_thread", "present", "swapchain", "rhi", "frame",
            "graphics", "renderer", "rendererthread", "rendercommand", "commandbuffer",
            "frametime", "scene", "shadow", "postprocess", "compositor"
        };

        private static readonly string[] AudioThreadPatterns = new[]
        {
            "audio", "sound", "fmod", "wwise", "xaudio", "openal",
            "audiothread", "audio_thread", "soundthread", "sound_thread",
            "mixer", "dsp", "wasapi"
        };

        private static readonly string[] NetworkThreadPatterns = new[]
        {
            "network", "net", "socket", "tcp", "udp", "http",
            "networkthread", "network_thread", "netthread", "net_thread",
            "connection", "packet"
        };

        private static readonly string[] WorkerThreadPatterns = new[]
        {
            "worker", "task", "job", "async", "pool",
            "workerthread", "worker_thread", "taskthread", "task_thread",
            "jobthread", "job_thread", "threadpool"
        };

        private static readonly string[] IOThreadPatterns = new[]
        {
            "io", "file", "disk", "load", "stream", "asset",
            "iothread", "io_thread", "filethread", "file_thread",
            "loading", "streaming"
        };

        #endregion

        #region Types

        public enum ThreadType
        {
            Unknown,
            Main,
            Render,
            Audio,
            Network,
            Worker,
            IO,
            Background,
            System
        }

        /// <summary>
        /// Behavioral metrics collected from thread runtime analysis.
        /// </summary>
        public class ThreadMetrics
        {
            public double CpuUsagePercent { get; set; }
            public ulong KernelTime { get; set; }
            public ulong UserTime { get; set; }
            public ulong CyclesDelta { get; set; }

            /// <summary>
            /// Ratio of kernel time to total time (0.0 = pure user, 1.0 = pure kernel).
            /// High kernel ratio = I/O or syscall heavy thread.
            /// </summary>
            public double KernelRatio { get; set; }

            /// <summary>
            /// Total CPU time delta (kernel + user) in 100ns ticks since last sample.
            /// </summary>
            public long TotalTimeDelta { get; set; }

            /// <summary>
            /// Thread creation time as FILETIME.
            /// </summary>
            public long CreationTime { get; set; }

            // Classification scores (0.0 - 1.0)
            public float RenderScore { get; set; }
            public float GameLogicScore { get; set; }
            public float AudioScore { get; set; }
            public float IOScore { get; set; }
        }

        public class GameThread
        {
            public int ThreadId { get; set; }
            public int ProcessId { get; set; }
            public ThreadType Type { get; set; }
            public string? Description { get; set; }
            public string? ModuleName { get; set; }
            public ulong StartAddress { get; set; }
            public int Priority { get; set; }
            public int ConfidenceScore { get; set; }
            public bool IsMainThread { get; set; }
            public ThreadMetrics? Metrics { get; set; }

            /// <summary>
            /// Recommended core type based on classification.
            /// </summary>
            public string CoreRecommendation =>
                Type switch
                {
                    ThreadType.Main => "P-Core",
                    ThreadType.Render => "P-Core",
                    ThreadType.Audio => "P-Core",
                    ThreadType.Network => "E-Core",
                    ThreadType.Worker => "E-Core",
                    ThreadType.IO => "E-Core",
                    ThreadType.Background => "E-Core",
                    _ => "Any"
                };

            public override string ToString()
            {
                string scores = Metrics != null
                    ? $" R:{Metrics.RenderScore:F2} G:{Metrics.GameLogicScore:F2} A:{Metrics.AudioScore:F2} IO:{Metrics.IOScore:F2} CPU:{Metrics.CpuUsagePercent:F1}% KR:{Metrics.KernelRatio:F2}"
                    : "";
                return $"Thread {ThreadId} [{Type}] Priority:{Priority} Desc:{Description ?? "N/A"} Module:{ModuleName ?? "N/A"} Confidence:{ConfidenceScore}{scores} -> {CoreRecommendation}";
            }
        }

        /// <summary>
        /// Tracks per-thread timing data across analysis passes for wake interval detection.
        /// </summary>
        private class ThreadTimingSnapshot
        {
            public int ThreadId;
            public long KernelTime;
            public long UserTime;
            public ulong Cycles;
            public DateTime Timestamp;
        }

        #endregion

        // Cross-call history for behavioral analysis
        private static readonly Dictionary<int, List<ThreadTimingSnapshot>> _threadHistory = new();
        private static long _lastSystemKernelTime;
        private static long _lastSystemUserTime;
        private static readonly object _historyLock = new();

        /// <summary>
        /// Detects and classifies all threads for a given game process.
        /// Uses both name-based heuristics and behavioral metrics.
        /// </summary>
        public static List<GameThread> DetectGameThreads(int processId, string processName)
        {
            var threads = new List<GameThread>();

            try
            {
                var process = Process.GetProcessById(processId);
                var moduleInfo = GetModuleInfo(processId);

                // Find the thread that owns the game's main window —
                // the single most reliable signal for the main/input thread
                int windowOwnerThreadId = FindWindowOwnerThread(processId);

                // Collect system timing baseline
                GetSystemTimes(out long sysIdle, out long sysKernel, out long sysUser);
                long systemTimeDelta = (sysKernel + sysUser) - (_lastSystemKernelTime + _lastSystemUserTime);
                int processorCount = Environment.ProcessorCount;

                foreach (ProcessThread thread in process.Threads)
                {
                    var gameThread = AnalyzeThread(thread, processId, processName, moduleInfo,
                        systemTimeDelta, processorCount, windowOwnerThreadId);
                    threads.Add(gameThread);
                }

                _lastSystemKernelTime = sysKernel;
                _lastSystemUserTime = sysUser;

                // Sort: main threads first, then by confidence
                threads = threads
                    .OrderByDescending(t => t.IsMainThread)
                    .ThenByDescending(t => t.ConfidenceScore)
                    .ThenByDescending(t => t.Priority)
                    .ToList();

                Logger.WriteVerbose($"[ThreadDetector] Analyzed {threads.Count} threads for {processName}", ConsoleColor.Cyan);

                foreach (var t in threads.Where(t => t.ConfidenceScore >= 50))
                {
                    Logger.WriteVerbose($"  [HIGH] {t}", ConsoleColor.Cyan);
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLog($"[ThreadDetector] Error detecting threads for PID {processId}: {ex.Message}");
            }

            return threads;
        }

        /// <summary>
        /// Get the main game thread(s) with high confidence.
        /// </summary>
        public static List<GameThread> GetMainThreads(int processId, string processName)
        {
            var allThreads = DetectGameThreads(processId, processName);
            return allThreads
                .Where(t => t.IsMainThread || t.Type == ThreadType.Main)
                .OrderByDescending(t => t.ConfidenceScore)
                .Take(2)
                .ToList();
        }

        /// <summary>
        /// Get threads recommended for P-cores (main + render + audio).
        /// </summary>
        public static List<GameThread> GetPCoreThreads(int processId, string processName)
        {
            var allThreads = DetectGameThreads(processId, processName);
            return allThreads
                .Where(t => t.Type == ThreadType.Main || t.Type == ThreadType.Render ||
                            t.Type == ThreadType.Audio || t.IsMainThread)
                .OrderByDescending(t => t.ConfidenceScore)
                .ToList();
        }

        /// <summary>
        /// Get threads recommended for E-cores (workers, network, IO, background).
        /// </summary>
        public static List<GameThread> GetECoreThreads(int processId, string processName)
        {
            var allThreads = DetectGameThreads(processId, processName);
            return allThreads
                .Where(t => t.Type == ThreadType.Worker || t.Type == ThreadType.Network ||
                            t.Type == ThreadType.IO || t.Type == ThreadType.Background ||
                            t.Type == ThreadType.System)
                .OrderByDescending(t => t.ConfidenceScore)
                .ToList();
        }

        /// <summary>
        /// Find the thread ID that owns the main visible window for a process.
        /// This is the most reliable way to identify the main/input thread.
        /// </summary>
        private static int FindWindowOwnerThread(int processId)
        {
            int ownerThreadId = 0;

            EnumWindows((hWnd, lParam) =>
            {
                if (!IsWindowVisible(hWnd))
                    return true;

                GetWindowThreadProcessId(hWnd, out uint windowPid);
                if (windowPid != (uint)processId)
                    return true;

                uint threadId = GetWindowThreadProcessId(hWnd, out _);
                ownerThreadId = (int)threadId;
                return true;
            }, IntPtr.Zero);

            // Prefer the foreground window's thread if it belongs to our process
            IntPtr fgWindow = GetForegroundWindow();
            if (fgWindow != IntPtr.Zero)
            {
                GetWindowThreadProcessId(fgWindow, out uint fgPid);
                if (fgPid == (uint)processId)
                {
                    uint fgThreadId = GetWindowThreadProcessId(fgWindow, out _);
                    ownerThreadId = (int)fgThreadId;
                }
            }

            return ownerThreadId;
        }

        private static GameThread AnalyzeThread(ProcessThread thread, int processId, string processName,
            Dictionary<ulong, string> moduleInfo, long systemTimeDelta, int processorCount,
            int windowOwnerThreadId)
        {
            var gameThread = new GameThread
            {
                ThreadId = thread.Id,
                ProcessId = processId,
                Type = ThreadType.Unknown,
                ConfidenceScore = 0
            };

            try
            {
                IntPtr hThread = OpenThread(THREAD_QUERY_INFORMATION, false, (uint)thread.Id);
                if (hThread == IntPtr.Zero)
                {
                    hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, (uint)thread.Id);
                }

                if (hThread != IntPtr.Zero)
                {
                    try
                    {
                        gameThread.Priority = GetThreadPriority(hThread);

                        if (TryGetThreadDescription(hThread, out string? desc))
                        {
                            gameThread.Description = desc;
                        }

                        if (TryGetStartAddress(hThread, out ulong startAddr))
                        {
                            gameThread.StartAddress = startAddr;
                            gameThread.ModuleName = ResolveModuleFromAddress(startAddr, moduleInfo);
                        }

                        // Collect behavioral metrics
                        gameThread.Metrics = CollectThreadMetrics(hThread, thread.Id,
                            systemTimeDelta, processorCount);
                    }
                    finally
                    {
                        CloseHandle(hThread);
                    }
                }

                // Phase 1: Name-based classification
                ClassifyByName(gameThread, processName);

                // Phase 2: Behavioral scoring (from C++ thread_analyzer logic)
                if (gameThread.Metrics != null)
                {
                    ComputeBehavioralScores(gameThread);
                    RefineClassificationFromScores(gameThread);
                }

                // Phase 3: Window-ownership main thread detection
                DetectMainThread(gameThread, thread, windowOwnerThreadId);
            }
            catch (Exception)
            {
                // Thread may have exited or be inaccessible
            }

            return gameThread;
        }

        /// <summary>
        /// Collect timing metrics for behavioral analysis.
        /// Tracks kernel/user time deltas and CPU cycles across calls.
        /// </summary>
        private static ThreadMetrics? CollectThreadMetrics(IntPtr hThread, int threadId,
            long systemTimeDelta, int processorCount)
        {
            var metrics = new ThreadMetrics();

            try
            {
                // Get thread times
                if (!GetThreadTimes(hThread, out long createTime, out long exitTime,
                        out long kernelTime, out long userTime))
                    return null;

                metrics.KernelTime = (ulong)kernelTime;
                metrics.UserTime = (ulong)userTime;
                metrics.CreationTime = createTime;

                // Get cycle time via NtQueryInformationThread
                var cycleInfo = new THREAD_CYCLE_TIME_INFORMATION();
                int status = NtQueryInformationThread(hThread, ThreadCycleTime,
                    ref cycleInfo, (uint)Marshal.SizeOf<THREAD_CYCLE_TIME_INFORMATION>(), out _);

                ulong currentCycles = status == 0 ? cycleInfo.AccumulatedCycles : 0;

                lock (_historyLock)
                {
                    if (!_threadHistory.TryGetValue(threadId, out var history))
                    {
                        history = new List<ThreadTimingSnapshot>();
                        _threadHistory[threadId] = history;
                    }

                    // Compute deltas from previous snapshot
                    if (history.Count > 0)
                    {
                        var prev = history[^1];
                        long kernelDelta = kernelTime - prev.KernelTime;
                        long userDelta = userTime - prev.UserTime;
                        long threadTimeDelta = kernelDelta + userDelta;

                        metrics.TotalTimeDelta = threadTimeDelta;

                        if (systemTimeDelta > 0)
                        {
                            metrics.CpuUsagePercent = 100.0 * threadTimeDelta / (systemTimeDelta / processorCount);
                        }

                        // Kernel-to-total ratio: how much time is in kernel mode
                        if (threadTimeDelta > 0)
                        {
                            metrics.KernelRatio = (double)kernelDelta / threadTimeDelta;
                        }

                        metrics.CyclesDelta = currentCycles - prev.Cycles;
                    }

                    // Store snapshot
                    history.Add(new ThreadTimingSnapshot
                    {
                        ThreadId = threadId,
                        KernelTime = kernelTime,
                        UserTime = userTime,
                        Cycles = currentCycles,
                        Timestamp = DateTime.UtcNow
                    });

                    // Keep last 10 samples (we use CPU time ratios, not wake intervals)
                    while (history.Count > 10)
                    {
                        history.RemoveAt(0);
                    }
                }
            }
            catch
            {
                return null;
            }

            return metrics;
        }

        /// <summary>
        /// Compute behavioral classification scores using CPU time profiles.
        ///
        /// Instead of measuring wake intervals (which required sub-ms sampling to
        /// be meaningful — the old 5s+ sampling interval produced garbage data that
        /// never matched frame-rate patterns), we use signals reliable at any rate:
        ///   - CPU utilization percentage
        ///   - Kernel-vs-user time ratio
        ///   - Cycle magnitude (computational intensity)
        ///   - Thread priority
        /// </summary>
        private static void ComputeBehavioralScores(GameThread thread)
        {
            var m = thread.Metrics!;

            m.RenderScore = 0.0f;
            m.GameLogicScore = 0.0f;
            m.AudioScore = 0.0f;
            m.IOScore = 0.0f;

            double cpu = m.CpuUsagePercent;
            double kr = m.KernelRatio;

            // === RENDER THREAD SCORING ===
            // High CPU, mostly user-mode (building GPU command buffers), high cycles
            {
                float cpuScore = cpu > 5.0 ? Math.Min(1.0f, (float)(cpu / 40.0)) : 0.0f;
                float userModeScore = kr < 0.3 ? 1.0f : kr < 0.5 ? 0.5f : 0.0f;
                float cycleScore = m.CyclesDelta > 50_000_000 ? 1.0f :
                                   m.CyclesDelta > 10_000_000 ? 0.6f :
                                   m.CyclesDelta > 1_000_000 ? 0.3f : 0.0f;

                m.RenderScore = cpuScore * 0.35f + userModeScore * 0.35f + cycleScore * 0.3f;

                string desc = (thread.Description ?? "").ToLowerInvariant();
                if (desc.Contains("render") || desc.Contains("rhi") || desc.Contains("d3d") ||
                    desc.Contains("frame") || desc.Contains("present") || desc.Contains("gpu"))
                {
                    m.RenderScore = Math.Min(1.0f, m.RenderScore + 0.3f);
                }
            }

            // === AUDIO THREAD SCORING ===
            // Low-moderate CPU, moderate kernel ratio (WASAPI calls), elevated priority
            {
                float cpuScore = (cpu > 0.5 && cpu < 10.0) ? 1.0f : 0.0f;
                float kernelScore = (kr > 0.2 && kr < 0.7) ? 1.0f : 0.3f;
                float prioScore = thread.Priority >= 2 ? 0.8f : thread.Priority >= 1 ? 0.5f : 0.2f;

                m.AudioScore = cpuScore * 0.3f + kernelScore * 0.3f + prioScore * 0.4f;

                string desc = (thread.Description ?? "").ToLowerInvariant();
                if (desc.Contains("audio") || desc.Contains("sound") || desc.Contains("wasapi") ||
                    desc.Contains("xaudio") || desc.Contains("fmod") || desc.Contains("wwise"))
                {
                    m.AudioScore = Math.Min(1.0f, m.AudioScore + 0.4f);
                }
            }

            // === GAME LOGIC THREAD SCORING ===
            // Highest CPU usage, mostly user-mode (physics, AI, scripting)
            {
                float cpuScore = cpu > 10.0 ? 1.0f :
                                 cpu > 5.0 ? 0.7f :
                                 cpu > 2.0 ? 0.4f : 0.0f;
                float userModeScore = kr < 0.2 ? 1.0f : kr < 0.4 ? 0.6f : 0.0f;
                float cycleScore = m.CyclesDelta > 100_000_000 ? 1.0f :
                                   m.CyclesDelta > 20_000_000 ? 0.6f :
                                   m.CyclesDelta > 5_000_000 ? 0.3f : 0.0f;

                m.GameLogicScore = cpuScore * 0.4f + userModeScore * 0.3f + cycleScore * 0.3f;

                string desc = (thread.Description ?? "").ToLowerInvariant();
                if (desc.Contains("game") || desc.Contains("logic") || desc.Contains("main") ||
                    desc.Contains("tick") || desc.Contains("update") || desc.Contains("simulation"))
                {
                    m.GameLogicScore = Math.Min(1.0f, m.GameLogicScore + 0.25f);
                }
            }

            // === IO THREAD SCORING ===
            // Low CPU, high kernel ratio (waiting in syscalls), low cycles
            {
                float cpuScore = cpu < 3.0 ? 1.0f : cpu < 8.0 ? 0.5f : 0.0f;
                float kernelScore = kr > 0.6 ? 1.0f : kr > 0.4 ? 0.5f : 0.0f;
                float cycleScore = m.CyclesDelta < 5_000_000 ? 1.0f :
                                   m.CyclesDelta < 20_000_000 ? 0.5f : 0.0f;

                m.IOScore = cpuScore * 0.3f + kernelScore * 0.4f + cycleScore * 0.3f;

                string desc = (thread.Description ?? "").ToLowerInvariant();
                if (desc.Contains("io") || desc.Contains("file") || desc.Contains("network") ||
                    desc.Contains("async") || desc.Contains("load") || desc.Contains("stream"))
                {
                    m.IOScore = Math.Min(1.0f, m.IOScore + 0.3f);
                }
            }
        }

        /// <summary>
        /// Refine thread classification using behavioral scores when they exceed
        /// the minimum threshold (0.3). Falls back to CPU-based heuristics.
        /// </summary>
        private static void RefineClassificationFromScores(GameThread thread)
        {
            var m = thread.Metrics!;
            float threshold = 0.4f;
            float maxScore = threshold;
            ThreadType bestType = thread.Type;

            if (m.RenderScore > maxScore)
            {
                maxScore = m.RenderScore;
                bestType = ThreadType.Render;
            }
            if (m.AudioScore > maxScore)
            {
                maxScore = m.AudioScore;
                bestType = ThreadType.Audio;
            }
            if (m.GameLogicScore > maxScore)
            {
                maxScore = m.GameLogicScore;
                bestType = ThreadType.Main;
            }
            if (m.IOScore > maxScore)
            {
                maxScore = m.IOScore;
                bestType = ThreadType.IO;
            }

            // Only override name-based classification if behavioral signal is strong
            if (bestType != thread.Type)
            {
                if (thread.Type == ThreadType.Unknown || maxScore >= 0.65f)
                {
                    thread.Type = bestType;
                    thread.ConfidenceScore += (int)(maxScore * 35);
                }
            }

            // CPU-based fallbacks for threads that remain Unknown
            if (thread.Type == ThreadType.Unknown)
            {
                if (m.CpuUsagePercent < 0.5 && m.CyclesDelta < 500_000)
                {
                    // Nearly idle — clearly background
                    thread.Type = ThreadType.Background;
                    thread.ConfidenceScore += 15;
                }
                else if (m.CpuUsagePercent >= 5.0 && m.KernelRatio < 0.3)
                {
                    // Significant user-mode CPU — likely a worker doing compute
                    thread.Type = ThreadType.Worker;
                    thread.ConfidenceScore += 20;
                }
                else if (m.CpuUsagePercent < 3.0 && m.KernelRatio > 0.5)
                {
                    // Low CPU, kernel-heavy — likely I/O
                    thread.Type = ThreadType.IO;
                    thread.ConfidenceScore += 15;
                }
                // If still Unknown, leave it alone — don't touch what we can't classify
            }
        }

        private static void ClassifyByName(GameThread thread, string processName)
        {
            string searchText = $"{thread.Description ?? ""} {thread.ModuleName ?? ""}".ToLowerInvariant();

            if (MatchesAnyPattern(searchText, MainThreadPatterns))
            {
                thread.Type = ThreadType.Main;
                thread.ConfidenceScore += 60;
            }
            else if (MatchesAnyPattern(searchText, RenderThreadPatterns))
            {
                thread.Type = ThreadType.Render;
                thread.ConfidenceScore += 50;
            }
            else if (MatchesAnyPattern(searchText, AudioThreadPatterns))
            {
                thread.Type = ThreadType.Audio;
                thread.ConfidenceScore += 40;
            }
            else if (MatchesAnyPattern(searchText, NetworkThreadPatterns))
            {
                thread.Type = ThreadType.Network;
                thread.ConfidenceScore += 30;
            }
            else if (MatchesAnyPattern(searchText, IOThreadPatterns))
            {
                thread.Type = ThreadType.IO;
                thread.ConfidenceScore += 30;
            }
            else if (MatchesAnyPattern(searchText, WorkerThreadPatterns))
            {
                thread.Type = ThreadType.Worker;
                thread.ConfidenceScore += 20;
            }

            // Module-based boost
            if (thread.ModuleName != null)
            {
                string moduleLower = thread.ModuleName.ToLowerInvariant();
                string processLower = processName.ToLowerInvariant();

                if (moduleLower.Contains(processLower) || moduleLower.EndsWith(".exe"))
                {
                    thread.ConfidenceScore += 20;
                }

                // Known engine modules
                if (moduleLower.Contains("unreal") || moduleLower.Contains("unity") ||
                    moduleLower.Contains("source") || moduleLower.Contains("cryengine") ||
                    moduleLower.Contains("frostbite") || moduleLower.Contains("id tech"))
                {
                    thread.ConfidenceScore += 15;
                }

                // Render module hints: prefer render/graphics classification over background classes
                if (moduleLower.Contains("d3d") || moduleLower.Contains("dxgi") || moduleLower.Contains("vulkan") ||
                    moduleLower.Contains("opengl") || moduleLower.Contains("nvwgf2") || moduleLower.Contains("atidxx") ||
                    moduleLower.Contains("render") || moduleLower.Contains("graphics"))
                {
                    if (thread.Type == ThreadType.Unknown || thread.Type == ThreadType.Worker || thread.Type == ThreadType.Background)
                    {
                        thread.Type = ThreadType.Render;
                    }
                    thread.ConfidenceScore += 20;
                }
            }

            // Priority-based boost
            if (thread.Priority >= 2)
            {
                thread.ConfidenceScore += 15;
                if (thread.Type == ThreadType.Unknown)
                {
                    thread.Type = ThreadType.Main;
                }
            }
            else if (thread.Priority <= -2)
            {
                thread.ConfidenceScore += 5;
                if (thread.Type == ThreadType.Unknown)
                {
                    thread.Type = ThreadType.Worker;
                }
            }
        }

        private static void DetectMainThread(GameThread thread, ProcessThread processThread, int windowOwnerThreadId)
        {
            try
            {
                // Signal 1: Window ownership — definitive identification.
                // The thread that owns the game's main window IS the input thread.
                if (windowOwnerThreadId > 0 && thread.ThreadId == windowOwnerThreadId)
                {
                    thread.IsMainThread = true;
                    thread.Type = ThreadType.Main;
                    thread.ConfidenceScore += 40;
                    return;
                }

                // Signal 2: Thread name
                if (thread.Description?.ToLowerInvariant().Contains("main") == true)
                {
                    thread.IsMainThread = true;
                    thread.ConfidenceScore += 30;
                    return;
                }

                // Signal 3: High priority + Main classification
                if (thread.Type == ThreadType.Main && thread.Priority >= 2)
                {
                    thread.IsMainThread = true;
                    thread.ConfidenceScore += 25;
                    return;
                }

                try
                {
                    if (processThread.ThreadState == System.Diagnostics.ThreadState.Running)
                    {
                        thread.ConfidenceScore += 5;
                    }
                }
                catch { }
            }
            catch { }
        }

        /// <summary>
        /// Clear accumulated thread history (call when game process exits).
        /// </summary>
        public static void ClearHistory()
        {
            lock (_historyLock)
            {
                _threadHistory.Clear();
                _lastSystemKernelTime = 0;
                _lastSystemUserTime = 0;
            }
        }

        /// <summary>
        /// Clear history for a specific process's threads.
        /// </summary>
        public static void ClearHistoryForProcess(int processId)
        {
            lock (_historyLock)
            {
                try
                {
                    var process = Process.GetProcessById(processId);
                    var threadIds = new HashSet<int>();
                    foreach (ProcessThread t in process.Threads)
                    {
                        threadIds.Add(t.Id);
                    }
                    var toRemove = _threadHistory.Keys.Where(k => threadIds.Contains(k)).ToList();
                    foreach (var key in toRemove)
                    {
                        _threadHistory.Remove(key);
                    }
                }
                catch
                {
                    // Process may have already exited
                }
            }
        }

        /// <summary>
        /// Prune history entries for threads that no longer exist.
        /// </summary>
        public static void PruneStaleHistory()
        {
            lock (_historyLock)
            {
                var staleIds = new List<int>();
                foreach (var threadId in _threadHistory.Keys)
                {
                    try
                    {
                        IntPtr hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, (uint)threadId);
                        if (hThread == IntPtr.Zero)
                            staleIds.Add(threadId);
                        else
                            CloseHandle(hThread);
                    }
                    catch { staleIds.Add(threadId); }
                }
                foreach (var id in staleIds)
                    _threadHistory.Remove(id);
            }
        }

        private static bool MatchesAnyPattern(string text, string[] patterns)
        {
            return patterns.Any(p => text.Contains(p));
        }

        private static Dictionary<ulong, string> GetModuleInfo(int processId)
        {
            var modules = new Dictionary<ulong, string>();

            try
            {
                IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (uint)processId);
                if (hProcess == IntPtr.Zero)
                    return modules;

                try
                {
                    IntPtr[] moduleHandles = new IntPtr[1024];
                    uint cbNeeded;

                    if (EnumProcessModulesEx(hProcess, moduleHandles, (uint)(moduleHandles.Length * IntPtr.Size), out cbNeeded, 0x03))
                    {
                        int numModules = (int)(cbNeeded / IntPtr.Size);
                        for (int i = 0; i < numModules && i < moduleHandles.Length; i++)
                        {
                            var sb = new StringBuilder(1024);
                            if (GetModuleFileNameEx(hProcess, moduleHandles[i], sb, (uint)sb.Capacity) > 0)
                            {
                                ulong baseAddr = unchecked((ulong)moduleHandles[i].ToInt64());
                                string moduleName = System.IO.Path.GetFileName(sb.ToString());
                                modules[baseAddr] = moduleName;
                            }
                        }
                    }
                }
                finally
                {
                    CloseHandle(hProcess);
                }
            }
            catch { }

            return modules;
        }

        private static string? ResolveModuleFromAddress(ulong address, Dictionary<ulong, string> moduleInfo)
        {
            foreach (var kvp in moduleInfo.OrderByDescending(k => k.Key))
            {
                if (address >= kvp.Key)
                {
                    return kvp.Value;
                }
            }
            return null;
        }

        private static bool TryGetThreadDescription(IntPtr hThread, out string? description)
        {
            description = null;
            try
            {
                int hr = GetThreadDescription(hThread, out IntPtr pDesc);
                if (hr >= 0 && pDesc != IntPtr.Zero)
                {
                    try
                    {
                        description = Marshal.PtrToStringUni(pDesc);
                        return !string.IsNullOrEmpty(description);
                    }
                    finally
                    {
                        LocalFree(pDesc);
                    }
                }
            }
            catch { }
            return false;
        }

        private static bool TryGetStartAddress(IntPtr hThread, out ulong startAddress)
        {
            startAddress = 0;
            try
            {
                IntPtr outPtr = IntPtr.Zero;
                uint returnLen;

                int status = NtQueryInformationThread(
                    hThread,
                    ThreadQuerySetWin32StartAddress,
                    ref outPtr,
                    (uint)IntPtr.Size,
                    out returnLen);

                if (status == 0)
                {
                    startAddress = unchecked((ulong)outPtr.ToInt64());
                    return true;
                }
            }
            catch { }
            return false;
        }

        public static string GenerateThreadSummary(List<GameThread> threads)
        {
            var summary = new StringBuilder();
            summary.AppendLine($"Thread Analysis Summary ({threads.Count} threads):");
            summary.AppendLine($"  Main:       {threads.Count(t => t.Type == ThreadType.Main || t.IsMainThread)}");
            summary.AppendLine($"  Render:     {threads.Count(t => t.Type == ThreadType.Render)}");
            summary.AppendLine($"  Audio:      {threads.Count(t => t.Type == ThreadType.Audio)}");
            summary.AppendLine($"  Network:    {threads.Count(t => t.Type == ThreadType.Network)}");
            summary.AppendLine($"  IO:         {threads.Count(t => t.Type == ThreadType.IO)}");
            summary.AppendLine($"  Worker:     {threads.Count(t => t.Type == ThreadType.Worker)}");
            summary.AppendLine($"  Background: {threads.Count(t => t.Type == ThreadType.Background)}");
            summary.AppendLine($"  Unknown:    {threads.Count(t => t.Type == ThreadType.Unknown)}");
            return summary.ToString().TrimEnd();
        }
    }
}
