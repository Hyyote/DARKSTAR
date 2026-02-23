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
            public double AverageWakeIntervalMs { get; set; }
            public double WakeIntervalVariance { get; set; }
            public int WakesPerSecond { get; set; }

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
                    ? $" R:{Metrics.RenderScore:F2} G:{Metrics.GameLogicScore:F2} A:{Metrics.AudioScore:F2} IO:{Metrics.IOScore:F2}"
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

                // Collect system timing baseline
                GetSystemTimes(out long sysIdle, out long sysKernel, out long sysUser);
                long systemTimeDelta = (sysKernel + sysUser) - (_lastSystemKernelTime + _lastSystemUserTime);
                int processorCount = Environment.ProcessorCount;

                foreach (ProcessThread thread in process.Threads)
                {
                    var gameThread = AnalyzeThread(thread, processId, processName, moduleInfo,
                        systemTimeDelta, processorCount);
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

                foreach (var t in threads.Where(t => t.ConfidenceScore >= 70))
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

        private static GameThread AnalyzeThread(ProcessThread thread, int processId, string processName,
            Dictionary<ulong, string> moduleInfo, long systemTimeDelta, int processorCount)
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

                // Phase 3: Main thread detection
                DetectMainThread(gameThread, thread);
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
                        long threadTimeDelta = (kernelTime - prev.KernelTime) + (userTime - prev.UserTime);

                        if (systemTimeDelta > 0)
                        {
                            metrics.CpuUsagePercent = 100.0 * threadTimeDelta / (systemTimeDelta / processorCount);
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

                    // Keep last 60 samples
                    while (history.Count > 60)
                    {
                        history.RemoveAt(0);
                    }

                    // Compute wake interval statistics from history
                    ComputeWakeIntervals(history, metrics);
                }
            }
            catch
            {
                return null;
            }

            return metrics;
        }

        /// <summary>
        /// Analyze timing history to detect wake interval patterns.
        /// Regular intervals suggest render/audio threads; irregular suggests IO/worker.
        /// </summary>
        private static void ComputeWakeIntervals(List<ThreadTimingSnapshot> history, ThreadMetrics metrics)
        {
            if (history.Count < 3)
                return;

            var intervals = new List<double>();
            for (int i = 1; i < history.Count; i++)
            {
                var prev = history[i - 1];
                var curr = history[i];

                // Look for activity by cycle delta
                if (curr.Cycles > prev.Cycles)
                {
                    double intervalMs = (curr.Timestamp - prev.Timestamp).TotalMilliseconds;
                    if (intervalMs > 0)
                    {
                        intervals.Add(intervalMs);
                    }
                }
            }

            if (intervals.Count == 0)
                return;

            double sum = 0;
            foreach (double v in intervals) sum += v;
            metrics.AverageWakeIntervalMs = sum / intervals.Count;

            // Variance
            double sqSum = 0;
            foreach (double v in intervals)
            {
                double diff = v - metrics.AverageWakeIntervalMs;
                sqSum += diff * diff;
            }
            metrics.WakeIntervalVariance = sqSum / intervals.Count;

            if (metrics.AverageWakeIntervalMs > 0)
            {
                metrics.WakesPerSecond = (int)(1000.0 / metrics.AverageWakeIntervalMs);
            }
        }

        /// <summary>
        /// Compute behavioral classification scores (ported from C++ thread_analyzer.cpp).
        /// Each score is 0.0 to 1.0 indicating likelihood of that thread type.
        /// </summary>
        private static void ComputeBehavioralScores(GameThread thread)
        {
            var m = thread.Metrics!;

            m.RenderScore = 0.0f;
            m.GameLogicScore = 0.0f;
            m.AudioScore = 0.0f;
            m.IOScore = 0.0f;

            // === RENDER THREAD SCORING ===
            // Render threads wake at regular frame intervals with high CPU usage
            {
                float intervalScore = 0.0f;
                float consistencyScore = 0.0f;

                // Common frame intervals (ms): 60fps=16.67, 120fps=8.33, 144fps=6.94, 90fps=11.11, 30fps=33.33
                double[] commonIntervals = { 16.67, 8.33, 6.94, 11.11, 33.33 };
                foreach (double target in commonIntervals)
                {
                    double diff = Math.Abs(m.AverageWakeIntervalMs - target);
                    if (diff < 2.0)
                    {
                        intervalScore = (float)(1.0 - diff / 2.0);
                        break;
                    }
                }

                // Low variance = consistent timing = likely render
                if (m.WakeIntervalVariance < 4.0 && m.AverageWakeIntervalMs > 0)
                {
                    consistencyScore = (float)(1.0 - m.WakeIntervalVariance / 4.0);
                }

                // High CPU with consistent timing
                float cpuScore = Math.Min(1.0f, (float)m.CpuUsagePercent / 30.0f);

                m.RenderScore = intervalScore * 0.4f + consistencyScore * 0.3f + cpuScore * 0.3f;

                // Name hint boost
                string desc = (thread.Description ?? "").ToLowerInvariant();
                if (desc.Contains("render") || desc.Contains("rhi") || desc.Contains("d3d") ||
                    desc.Contains("frame") || desc.Contains("present") || desc.Contains("gpu"))
                {
                    m.RenderScore = Math.Min(1.0f, m.RenderScore + 0.3f);
                }
            }

            // === AUDIO THREAD SCORING ===
            // Very consistent short intervals (5-10ms), low CPU
            {
                float intervalScore = 0.0f;

                // Audio typically runs at 5-10ms intervals
                if (m.AverageWakeIntervalMs >= 3.0 && m.AverageWakeIntervalMs <= 15.0)
                {
                    intervalScore = 1.0f;
                }

                // Extremely consistent (audio buffers are precise)
                float consistencyScore = m.WakeIntervalVariance < 1.0 ? 1.0f : 0.0f;

                // Audio threads typically use less CPU
                float cpuScore = (m.CpuUsagePercent > 1.0 && m.CpuUsagePercent < 10.0) ? 1.0f : 0.0f;

                m.AudioScore = intervalScore * 0.4f + consistencyScore * 0.4f + cpuScore * 0.2f;

                // Name hints
                string desc = (thread.Description ?? "").ToLowerInvariant();
                if (desc.Contains("audio") || desc.Contains("sound") || desc.Contains("wasapi") ||
                    desc.Contains("xaudio") || desc.Contains("fmod") || desc.Contains("wwise"))
                {
                    m.AudioScore = Math.Min(1.0f, m.AudioScore + 0.4f);
                }
            }

            // === GAME LOGIC THREAD SCORING ===
            // Similar interval to render (tied to game tick), higher variance, significant CPU
            {
                float intervalScore = 0.0f;

                // Game logic often matches render rate or runs at fixed tick rates
                double[] tickIntervals = { 16.67, 33.33, 20.0, 16.0, 15.0 };
                foreach (double target in tickIntervals)
                {
                    if (Math.Abs(m.AverageWakeIntervalMs - target) < 3.0)
                    {
                        intervalScore = 0.8f;
                        break;
                    }
                }

                // Some variance is expected in game logic (physics, AI, etc.)
                float varianceScore = (m.WakeIntervalVariance > 1.0 && m.WakeIntervalVariance < 20.0) ? 0.7f : 0.3f;

                float cpuScore = Math.Min(1.0f, (float)m.CpuUsagePercent / 25.0f);

                m.GameLogicScore = intervalScore * 0.35f + varianceScore * 0.25f + cpuScore * 0.4f;

                // Name hints
                string desc = (thread.Description ?? "").ToLowerInvariant();
                if (desc.Contains("game") || desc.Contains("logic") || desc.Contains("main") ||
                    desc.Contains("tick") || desc.Contains("update") || desc.Contains("simulation"))
                {
                    m.GameLogicScore = Math.Min(1.0f, m.GameLogicScore + 0.25f);
                }
            }

            // === IO THREAD SCORING ===
            // Irregular wake pattern, low CPU, event-driven
            {
                // High variance = event-driven
                float varianceScore = m.WakeIntervalVariance > 50.0
                    ? 1.0f
                    : (float)(m.WakeIntervalVariance / 50.0);

                // Low CPU when active
                float cpuScore = m.CpuUsagePercent < 5.0 ? 1.0f : 0.0f;

                m.IOScore = varianceScore * 0.5f + cpuScore * 0.5f;

                // Name hints
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
            float threshold = 0.3f;
            float maxScore = threshold;
            ThreadType bestType = thread.Type; // Keep name-based classification as default

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

            // Only override if behavioral analysis found something above threshold
            // AND the current type is Unknown or the behavioral score is very high
            if (bestType != thread.Type)
            {
                if (thread.Type == ThreadType.Unknown || maxScore >= 0.6f)
                {
                    thread.Type = bestType;
                    thread.ConfidenceScore += (int)(maxScore * 40);
                }
            }

            // CPU-based fallbacks for threads that remain Unknown
            if (thread.Type == ThreadType.Unknown)
            {
                if (m.CpuUsagePercent < 1.0)
                {
                    thread.Type = ThreadType.Background;
                    thread.ConfidenceScore += 10;
                }
                else if (m.CpuUsagePercent < 15.0)
                {
                    thread.Type = ThreadType.Worker;
                    thread.ConfidenceScore += 15;
                }
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

        private static void DetectMainThread(GameThread thread, ProcessThread processThread)
        {
            try
            {
                if (thread.Description?.ToLowerInvariant().Contains("main") == true)
                {
                    thread.IsMainThread = true;
                    thread.ConfidenceScore += 30;
                    return;
                }

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
                        thread.ConfidenceScore += 10;
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
