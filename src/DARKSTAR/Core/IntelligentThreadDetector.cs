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
    /// Intelligent game thread detector inspired by DARKSTAR's approach.
    /// Analyzes thread characteristics to identify main game threads, render threads,
    /// and other important threads for optimal affinity assignment.
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

        [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
        private static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, StringBuilder lpFilename, uint nSize);

        [DllImport("psapi.dll")]
        private static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded, uint dwFilterFlag);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        private const uint THREAD_QUERY_INFORMATION = 0x0040;
        private const uint THREAD_QUERY_LIMITED_INFORMATION = 0x0800;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;
        private const int ThreadQuerySetWin32StartAddress = 9;

        #endregion

        /// <summary>
        /// Known game thread patterns for intelligent detection
        /// </summary>
        private static readonly string[] MainThreadPatterns = new[]
        {
            "main", "gamethread", "game_thread", "mainthread", "main_thread",
            "primarythread", "primary_thread", "gameloop", "game_loop"
        };

        private static readonly string[] RenderThreadPatterns = new[]
        {
            "render", "gpu", "dx11", "dx12", "d3d", "vulkan", "opengl",
            "renderthread", "render_thread", "graphicsthread", "graphics_thread",
            "drawthread", "draw_thread", "present", "swapchain"
        };

        private static readonly string[] AudioThreadPatterns = new[]
        {
            "audio", "sound", "fmod", "wwise", "xaudio", "openal",
            "audiothread", "audio_thread", "soundthread", "sound_thread",
            "mixer", "dsp"
        };

        private static readonly string[] NetworkThreadPatterns = new[]
        {
            "network", "net", "socket", "tcp", "udp", "http",
            "networkthread", "network_thread", "netthread", "net_thread",
            "connection", "packet"
        };

        private static readonly string[] WorkerThreadPatterns = new[]
        {
            "worker", "task", "job", "thread", "async", "pool",
            "workerthread", "worker_thread", "taskthread", "task_thread",
            "jobthread", "job_thread", "threadpool"
        };

        /// <summary>
        /// Represents a detected game thread with its classification
        /// </summary>
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

            public override string ToString()
            {
                return $"Thread {ThreadId} [{Type}] Priority:{Priority} Desc:{Description ?? "N/A"} Module:{ModuleName ?? "N/A"} Confidence:{ConfidenceScore}";
            }
        }

        public enum ThreadType
        {
            Unknown,
            Main,
            Render,
            Audio,
            Network,
            Worker,
            System
        }

        /// <summary>
        /// Detects and classifies all threads for a given game process
        /// </summary>
        public static List<GameThread> DetectGameThreads(int processId, string processName)
        {
            var threads = new List<GameThread>();

            try
            {
                var process = Process.GetProcessById(processId);
                var moduleInfo = GetModuleInfo(processId);

                foreach (ProcessThread thread in process.Threads)
                {
                    var gameThread = AnalyzeThread(thread, processId, processName, moduleInfo);
                    threads.Add(gameThread);
                }

                // Sort by confidence score (main threads first, then by priority)
                threads = threads
                    .OrderByDescending(t => t.IsMainThread)
                    .ThenByDescending(t => t.ConfidenceScore)
                    .ThenByDescending(t => t.Priority)
                    .ToList();

                Logger.WriteVerbose($"[ThreadDetector] Analyzed {threads.Count} threads for {processName}", ConsoleColor.Cyan);

                // Log high-confidence detections
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
        /// Get the main game thread(s) with high confidence
        /// </summary>
        public static List<GameThread> GetMainThreads(int processId, string processName)
        {
            var allThreads = DetectGameThreads(processId, processName);
            return allThreads
                .Where(t => t.IsMainThread || t.Type == ThreadType.Main)
                .OrderByDescending(t => t.ConfidenceScore)
                .Take(2) // Usually 1-2 main threads
                .ToList();
        }

        /// <summary>
        /// Get recommended P-core threads (main + render threads)
        /// </summary>
        public static List<GameThread> GetPCoreThreads(int processId, string processName)
        {
            var allThreads = DetectGameThreads(processId, processName);
            return allThreads
                .Where(t => t.Type == ThreadType.Main || t.Type == ThreadType.Render || t.IsMainThread)
                .OrderByDescending(t => t.ConfidenceScore)
                .ToList();
        }

        /// <summary>
        /// Get recommended E-core threads (workers, network, etc.)
        /// </summary>
        public static List<GameThread> GetECoreThreads(int processId, string processName)
        {
            var allThreads = DetectGameThreads(processId, processName);
            return allThreads
                .Where(t => t.Type == ThreadType.Worker || t.Type == ThreadType.Network || t.Type == ThreadType.System)
                .OrderByDescending(t => t.ConfidenceScore)
                .ToList();
        }

        private static GameThread AnalyzeThread(ProcessThread thread, int processId, string processName, Dictionary<ulong, string> moduleInfo)
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
                // Get thread handle
                IntPtr hThread = OpenThread(THREAD_QUERY_INFORMATION, false, (uint)thread.Id);
                if (hThread == IntPtr.Zero)
                {
                    hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, (uint)thread.Id);
                }

                if (hThread != IntPtr.Zero)
                {
                    try
                    {
                        // Get priority
                        gameThread.Priority = GetThreadPriority(hThread);

                        // Get description
                        if (TryGetThreadDescription(hThread, out string? desc))
                        {
                            gameThread.Description = desc;
                        }

                        // Get start address and resolve module
                        if (TryGetStartAddress(hThread, out ulong startAddr))
                        {
                            gameThread.StartAddress = startAddr;
                            gameThread.ModuleName = ResolveModuleFromAddress(startAddr, moduleInfo);
                        }
                    }
                    finally
                    {
                        CloseHandle(hThread);
                    }
                }

                // Classify thread
                ClassifyThread(gameThread, processName);

                // Detect main thread
                DetectMainThread(gameThread, thread);
            }
            catch (Exception)
            {
                // Thread may have exited or be inaccessible
            }

            return gameThread;
        }

        private static void ClassifyThread(GameThread thread, string processName)
        {
            string searchText = $"{thread.Description ?? ""} {thread.ModuleName ?? ""}".ToLowerInvariant();
            string processLower = processName.ToLowerInvariant();

            // Check for main thread patterns
            if (MatchesAnyPattern(searchText, MainThreadPatterns))
            {
                thread.Type = ThreadType.Main;
                thread.ConfidenceScore += 60;
            }
            // Check for render thread patterns
            else if (MatchesAnyPattern(searchText, RenderThreadPatterns))
            {
                thread.Type = ThreadType.Render;
                thread.ConfidenceScore += 50;
            }
            // Check for audio thread patterns
            else if (MatchesAnyPattern(searchText, AudioThreadPatterns))
            {
                thread.Type = ThreadType.Audio;
                thread.ConfidenceScore += 40;
            }
            // Check for network thread patterns
            else if (MatchesAnyPattern(searchText, NetworkThreadPatterns))
            {
                thread.Type = ThreadType.Network;
                thread.ConfidenceScore += 30;
            }
            // Check for worker thread patterns
            else if (MatchesAnyPattern(searchText, WorkerThreadPatterns))
            {
                thread.Type = ThreadType.Worker;
                thread.ConfidenceScore += 20;
            }

            // Module-based classification boost
            if (thread.ModuleName != null)
            {
                string moduleLower = thread.ModuleName.ToLowerInvariant();
                
                // If thread is from the game's main executable, boost confidence
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
            }

            // Priority-based boost
            if (thread.Priority >= 2) // Above normal
            {
                thread.ConfidenceScore += 15;
                if (thread.Type == ThreadType.Unknown)
                {
                    thread.Type = ThreadType.Main; // High priority unknown threads are likely important
                }
            }
            else if (thread.Priority <= -2) // Below normal
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
                // Check if this is likely the main thread
                // Heuristics:
                // 1. Thread with highest priority in the process
                // 2. Thread that started first (lowest ID often, though not guaranteed)
                // 3. Thread description contains "main"

                if (thread.Description?.ToLowerInvariant().Contains("main") == true)
                {
                    thread.IsMainThread = true;
                    thread.ConfidenceScore += 30;
                    return;
                }

                // High priority threads that are classified as Main type
                if (thread.Type == ThreadType.Main && thread.Priority >= 2)
                {
                    thread.IsMainThread = true;
                    thread.ConfidenceScore += 25;
                    return;
                }

                // Use wait reason to detect active threads
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
            // Find the module that contains this address (simple approximation)
            // In reality, we'd need module base + size info
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

        /// <summary>
        /// Generates a summary of thread analysis for logging
        /// </summary>
        public static string GenerateThreadSummary(List<GameThread> threads)
        {
            var summary = new StringBuilder();
            summary.AppendLine($"Thread Analysis Summary ({threads.Count} threads):");
            summary.AppendLine($"  Main:    {threads.Count(t => t.Type == ThreadType.Main || t.IsMainThread)}");
            summary.AppendLine($"  Render:  {threads.Count(t => t.Type == ThreadType.Render)}");
            summary.AppendLine($"  Audio:   {threads.Count(t => t.Type == ThreadType.Audio)}");
            summary.AppendLine($"  Network: {threads.Count(t => t.Type == ThreadType.Network)}");
            summary.AppendLine($"  Worker:  {threads.Count(t => t.Type == ThreadType.Worker)}");
            summary.AppendLine($"  Unknown: {threads.Count(t => t.Type == ThreadType.Unknown)}");
            return summary.ToString();
        }
    }
}
