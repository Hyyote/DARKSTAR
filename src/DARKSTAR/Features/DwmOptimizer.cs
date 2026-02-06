using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DARKSTAR.Features
{
    public static class DwmOptimizer
    {
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
        private const int DWM_FORCE_INTERVAL = 50;

        private static readonly Dictionary<string, DateTime> _lastDwmSetTime = new Dictionary<string, DateTime>();

        public static void OptimizeDwmThread(ProcessThread thread, int targetPriority, string affinityStr, string name)
        {
            IntPtr threadHandle = OpenThread(THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, false, (uint)thread.Id);
            if (threadHandle != IntPtr.Zero)
            {
                try
                {
                    int currentPrio = GetThreadPriority(threadHandle);
                    if (currentPrio != targetPriority)
                    {
                        SetThreadPriority(threadHandle, targetPriority);
                        SetThreadPriorityBoost(threadHandle, true);
                        IntPtr affinity = Core.AffinityParser.Parse(affinityStr);
                        SetThreadAffinityMask(threadHandle, affinity);
                        _lastDwmSetTime[$"{thread.Id}_{name}"] = DateTime.Now;

                        int checkPrio = GetThreadPriority(threadHandle);
                    }
                }
                finally
                {
                    CloseHandle(threadHandle);
                }
            }
            else
            {
                // DWM is PPL-protected - fall back to kernel driver
                if (Core.ConfigLoader.UseKernelDriver && Core.KernelDriverInterface.IsPplBypassAvailable)
                {
                    bool prioritySet = Core.KernelDriverInterface.SetThreadPriority(thread.Id, targetPriority);
                    
                    IntPtr affinity = Core.AffinityParser.Parse(affinityStr);
                    bool affinitySet = Core.KernelDriverInterface.SetThreadAffinity(thread.Id, affinity);
                    
                    if (prioritySet || affinitySet)
                    {
                        _lastDwmSetTime[$"{thread.Id}_{name}"] = DateTime.Now;
                    }
                }
            }
        }

        public static void ApplyPersistentThreadOptimizations()
        {
            try
            {
                var now = DateTime.Now;
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
                                string threadKey = $"{process.Id}_{thread.Id}";
                                if (_lastDwmSetTime.TryGetValue(threadKey, out DateTime lastSet) &&
                                    (now - lastSet).TotalMilliseconds < DWM_FORCE_INTERVAL)
                                    continue;

                                if (threadName == "DWM Kernel Sensor Thread")
                                {
                                    OptimizeDwmThread(thread, -2, "1,3,5,7", threadKey);
                                }
                                else if (threadName == "DWM Master Input Thread")
                                {
                                    OptimizeDwmThread(thread, 15, "0,2,4,6", threadKey);
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        public static void CleanupTracking()
        {
            try
            {
                var now = DateTime.Now;
                var toRemove = new List<string>();
                foreach (var kvp in _lastDwmSetTime)
                {
                    if ((now - kvp.Value).TotalMinutes > 5)
                    {
                        toRemove.Add(kvp.Key);
                    }
                }
                foreach (string key in toRemove)
                {
                    _lastDwmSetTime.Remove(key);
                }
            }
            catch { }
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
                if (result >= 0 && namePtr != IntPtr.Zero)  // HRESULT: S_OK (0) = success, check >= 0
                {
                    string? name = Marshal.PtrToStringUni(namePtr);
                    return string.IsNullOrEmpty(name) ? "EMPTY" : name!;
                }

                return "NO_NAME";
            }
            finally
            {
                if (namePtr != IntPtr.Zero)
                    LocalFree(namePtr);  // FIXED: GetThreadDescription uses LocalAlloc, not CoTaskMemAlloc
                if (threadHandle != IntPtr.Zero)
                    CloseHandle(threadHandle);
            }
        }
    }
}
