using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using DARKSTAR.Core.Native;
using DARKSTAR.Features.Native;

namespace DARKSTAR.Core
{
    public static class MonitoringEngine
    {
        #region P/Invoke Declarations
        [DllImport("kernel32.dll")]
        private static extern int GetThreadPriority(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        private static extern bool SetProcessAffinityMask(IntPtr hProcess, IntPtr dwProcessAffinityMask);

        [DllImport("kernel32.dll")]
        private static extern bool SetPriorityClass(IntPtr hProcess, uint dwPriorityClass);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetThreadPriority(IntPtr hThread, int nPriority);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr SetThreadAffinityMask(IntPtr hThread, IntPtr dwThreadAffinityMask);

        [DllImport("kernel32.dll")]
        private static extern bool SetProcessPriorityBoost(IntPtr hProcess, bool bDisablePriorityBoost);

        [DllImport("kernel32.dll")]
        private static extern bool SetThreadPriorityBoost(IntPtr hThread, bool bDisablePriorityBoost);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int GetThreadDescription(IntPtr hThread, out IntPtr ppszThreadDescription);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("psapi.dll")]
        private static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded, uint dwFilterFlag);

        [DllImport("psapi.dll")]
        private static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpFilename, uint nSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool LookupPrivilegeValue(string? lpSystemName, string? lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        #region Structures
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[]? Privileges;
        }
        #endregion

        private const uint THREAD_QUERY_LIMITED_INFORMATION = 0x0800;
        private const uint THREAD_SET_INFORMATION = 0x0020;
        private const uint THREAD_QUERY_INFORMATION = 0x0040;
        private const uint THREAD_SUSPEND_RESUME = 0x0002;
        private const uint THREAD_TERMINATE = 0x0001;
        private const uint PROCESS_SET_INFORMATION = 0x0200;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint LIST_MODULES_ALL = 0x03;

        private const uint REALTIME_PRIORITY_CLASS = 0x00000100;
        private const uint HIGH_PRIORITY_CLASS = 0x00000080;
        private const uint ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000;
        private const uint NORMAL_PRIORITY_CLASS = 0x00000020;
        private const uint BELOW_NORMAL_PRIORITY_CLASS = 0x00004000;
        private const uint IDLE_PRIORITY_CLASS = 0x00000040;

        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_QUERY = 0x0008;

        private const int CHECK_INTERVAL = 2000;
        private const int FAST_CHECK_INTERVAL = 500;
        private const int SLOW_CHECK_INTERVAL = 5000;
        private const int SYSTEM_PROCESS_CHECK_INTERVAL = 10000;
        private const int MAX_REVERT_ATTEMPTS = 3;
        private const int THREAD_PRIORITY_HIGH_VALUE = 2;          // Windows: THREAD_PRIORITY_HIGHEST
        private const int THREAD_PRIORITY_ABOVE_NORMAL_VALUE = 1;  // Windows: THREAD_PRIORITY_ABOVE_NORMAL
        private const int THREAD_PRIORITY_BELOW_NORMAL_VALUE = -1; // Windows: THREAD_PRIORITY_BELOW_NORMAL

        #endregion

        #region State
        private static readonly HashSet<int> _processedProcesses = new HashSet<int>();
        private static readonly Dictionary<int, HashSet<string>> _pendingThreads = new Dictionary<int, HashSet<string>>();
        private static readonly HashSet<int> _ignoredSecondaryProcesses = new HashSet<int>();
        private static readonly HashSet<int> _disableBoostApplied = new HashSet<int>();

        private static readonly Dictionary<int, Dictionary<int, int>> _threadPriorityHistory = new Dictionary<int, Dictionary<int, int>>();
        private static readonly HashSet<int> _blacklistedThreads = new HashSet<int>();
        private static readonly Dictionary<int, int> _threadRevertCounts = new Dictionary<int, int>();
        private static readonly Dictionary<int, DateTime> _lastThreadOperationTime = new Dictionary<int, DateTime>();
        private static readonly HashSet<int> _permanentlyTerminatedThreads = new HashSet<int>();
        private static readonly Dictionary<int, int> _threadSuspendCounts = new Dictionary<int, int>();
        private static readonly Dictionary<int, int> _threadMonitoringCycles = new Dictionary<int, int>();

        private static readonly Dictionary<string, int> _processWatcherCycles = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, Dictionary<string, int>> _threadWatcherCycles = new Dictionary<string, Dictionary<string, int>>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, bool> _processWatcherActive = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, bool> _threadWatcherActive = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        private static bool _gameOptimized = false;
        private static int _gameProcessId = -1;
        private static bool _forceSystemOptimizations = false;

        private static bool _autoCapsAppliedThisGameSession = false;

        private static DateTime _lastFastCheck = DateTime.MinValue;
        private static DateTime _lastSlowCheck = DateTime.MinValue;
        private static DateTime _lastRevertCheck = DateTime.MinValue;
        private static DateTime _lastSystemProcessCheck = DateTime.MinValue;

        private static readonly Dictionary<int, HashSet<string>> _appliedModuleThreads = new Dictionary<int, HashSet<string>>();
        
        private static readonly HashSet<int> _kernelModeFailedThreads = new HashSet<int>();
        
        // Pending game initializations (non-blocking approach)
        private static readonly Dictionary<int, (Process Process, string ProcessName, Dictionary<string, ProcessConfig> Configs, DateTime InitTime)> _pendingGameInit = 
            new Dictionary<int, (Process, string, Dictionary<string, ProcessConfig>, DateTime)>();
        
        // Lock objects for thread-safe cleanup
        private static readonly object _threadMonitoringCyclesLock = new object();
        private static readonly object _appliedModuleThreadsLock = new object();
        private static readonly object _disableBoostAppliedLock = new object();
        private static readonly object _pendingGameInitLock = new object();
        #endregion

        public static bool GameOptimized => _gameOptimized;
        public static int GameProcessId => _gameProcessId;
        public static bool ForceSystemOptimizations => _forceSystemOptimizations;

        public static void Start()
        {
            Thread monitoringThread = new Thread(MonitoringLoop);
            monitoringThread.IsBackground = true;
            monitoringThread.Start();
        }

        private static void MonitoringLoop()
        {
            bool isAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            if (!isAdmin)
            {
                Logger.WriteColored("WARNING: Not running as administrator. Access to system processes may be limited.", ConsoleColor.Cyan);
                Logger.WriteLog("WARNING: Not running as administrator");
            }
            else
            {
                if (EnablePrivilege("SeDebugPrivilege"))
                {
                    Logger.WriteVerbose("SeDebugPrivilege enabled successfully.", ConsoleColor.Cyan);
                    Logger.WriteLog("SeDebugPrivilege enabled successfully");
                }
            }
            
            // Initialize kernel driver if enabled in configuration
            if (ConfigLoader.UseKernelDriver)
            {
                if (KernelDriverInterface.Initialize())
                {
                    Logger.WriteMinimal($"✓ Kernel driver connected: {KernelDriverInterface.DriverVersion}", ConsoleColor.Green);
                    Logger.WriteMinimal("  Thread priority modifications will use kernel mode", ConsoleColor.Cyan);
                }
                else
                {
                    Logger.WriteMinimal("⚠ Kernel driver not available - using user-mode (limited on protected processes)", ConsoleColor.Yellow);
                    Logger.WriteMinimal("  For full functionality, run Process Hacker with kernel driver enabled", ConsoleColor.Yellow);
                }
            }

            while (true)
            {
                try
                {
                    CheckHotkeys();

                    var now = DateTime.Now;

                    if ((now - _lastFastCheck).TotalMilliseconds >= FAST_CHECK_INTERVAL)
                    {
                        CheckForThreadReverts();
                        Features.GpuPriorityManager.ReapplyGpuPriorities();
                        CheckPendingGameInitializations();  // Non-blocking game init check
                        _lastFastCheck = now;
                    }

                    if ((now - _lastRevertCheck).TotalMilliseconds >= 20000)
                    {
                        CheckForThreadReverts();
                        _lastRevertCheck = now;
                    }

                    if ((now - _lastSlowCheck).TotalMilliseconds >= SLOW_CHECK_INTERVAL)
                    {
                        CheckForConfiguredProcesses();
                        CheckPendingThreads();
                        CleanupThreadOperationTracking();
                        MonitorMemoryCapsForTargetProcesses();
                        _lastSlowCheck = now;
                    }

                    if ((now - _lastSystemProcessCheck).TotalMilliseconds >= SYSTEM_PROCESS_CHECK_INTERVAL)
                    {
                        CheckForNewSystemProcesses();
                        RunSmartProcessWatchers();
                        _lastSystemProcessCheck = now;
                    }

                    Thread.Sleep(50);
                }
                catch (Exception ex)
                {
                    Logger.WriteColored($"Error in monitoring loop: {ex.Message}", ConsoleColor.Cyan);
                    Logger.WriteLog($"Error in monitoring loop: {ex.Message}");
                    Thread.Sleep(CHECK_INTERVAL);
                }
            }
        }

        private static void CheckHotkeys()
        {
            HotkeyManager.CheckHotkeys();
        }

        public static void ToggleForceSystemOptimizations()
        {
            _forceSystemOptimizations = !_forceSystemOptimizations;
            if (_forceSystemOptimizations)
            {
                Logger.WriteColored("SYSTEM OPTIMIZATIONS FORCED BY USER (Ctrl+Shift+G)", ConsoleColor.Cyan);
                Logger.WriteLog("SYSTEM OPTIMIZATIONS FORCED BY USER (Ctrl+Shift+G)");
                CheckForConfiguredProcesses();
            }
            else
            {
                Logger.WriteColored("SYSTEM OPTIMIZATIONS RETURNED TO NORMAL MODE", ConsoleColor.Cyan);
                Logger.WriteLog("SYSTEM OPTIMIZATIONS RETURNED TO NORMAL MODE");
            }
        }

        private static void RunSmartProcessWatchers()
        {
            CheckMissingProcesses();
            CheckMissingThreads();
        }

        private static void CheckMissingProcesses()
        {
            try
            {
                if (!_gameOptimized && !_forceSystemOptimizations)
                    return;

                var processesToRemove = new List<string>();

                foreach (var processName in ConfigLoader.GameConfigs.Keys.Concat(ConfigLoader.SystemConfigs.Keys))
                {
                    if (!_processWatcherActive.ContainsKey(processName))
                    {
                        _processWatcherActive[processName] = false;
                        _processWatcherCycles[processName] = 0;
                    }

                    if (!_processWatcherActive[processName])
                    {
                        if ((_gameOptimized && ConfigLoader.GameConfigs.ContainsKey(processName)) ||
                            ((_gameOptimized || _forceSystemOptimizations) && ConfigLoader.SystemConfigs.ContainsKey(processName)))
                        {
                            _processWatcherActive[processName] = true;
                            _processWatcherCycles[processName] = 0;
                            Logger.WriteVerbose($"Process watcher activated for: {processName}", ConsoleColor.DarkCyan);
                            Logger.WriteLog($"Process watcher activated for: {processName}");
                        }
                        continue;
                    }

                    if (!_processWatcherActive[processName])
                        continue;

                    if (Process.GetProcessesByName(processName).Length > 0)
                    {
                        if (_processWatcherCycles[processName] > 0)
                        {
                            _processWatcherCycles[processName] = 0;
                            Logger.WriteVerbose($"Process watcher reset: {processName} found", ConsoleColor.Cyan);
                            Logger.WriteLog($"Process watcher reset: {processName} found");
                        }
                        continue;
                    }

                    _processWatcherCycles[processName]++;

                    Logger.WriteVerbose($"Process watcher: {processName} not found (cycle {_processWatcherCycles[processName]}/4)", ConsoleColor.Cyan);
                    Logger.WriteLog($"Process watcher: {processName} not found (cycle {_processWatcherCycles[processName]}/4)");

                    if (_processWatcherCycles[processName] >= 4)
                    {
                        Logger.WriteColored($"Process watcher stopped: {processName} not found after 4 cycles", ConsoleColor.Cyan);
                        Logger.WriteLog($"Process watcher stopped: {processName} not found after 4 cycles");
                        _processWatcherActive[processName] = false;
                        processesToRemove.Add(processName);
                    }
                }

                foreach (var processName in processesToRemove)
                {
                    _processWatcherCycles.Remove(processName);
                    _processWatcherActive.Remove(processName);
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLog($"Error in CheckMissingProcesses: {ex.Message}");
            }
        }

        private static void CheckMissingThreads()
        {
            try
            {
                if (!_gameOptimized && !_forceSystemOptimizations)
                    return;

                var threadsToRemove = new List<(string processName, string threadName)>();

                lock (_pendingThreads)
                {
                    foreach (var kvp in _pendingThreads.ToList())
                    {
                        int processId = kvp.Key;
                        var pendingThreads = kvp.Value;

                        string? processName = GetProcessName(processId);
                        if (processName == null)
                        {
                            _pendingThreads.Remove(processId);
                            continue;
                        }

                        foreach (var threadName in pendingThreads.ToList())
                        {
                            string threadKey = $"{processId}_{threadName}";

                            if (!_threadWatcherActive.ContainsKey(threadKey))
                            {
                                _threadWatcherActive[threadKey] = false;
                                if (!_threadWatcherCycles.ContainsKey(processName))
                                    _threadWatcherCycles[processName] = new Dictionary<string, int>();

                                _threadWatcherCycles[processName][threadName] = 0;
                            }

                            if (!_threadWatcherActive[threadKey] && _processedProcesses.Contains(processId))
                            {
                                _threadWatcherActive[threadKey] = true;
                                _threadWatcherCycles[processName][threadName] = 0;
                                Logger.WriteVerbose($"Thread watcher activated: {processName} -> {threadName}", ConsoleColor.DarkCyan);
                                Logger.WriteLog($"Thread watcher activated: {processName} -> {threadName}");
                            }

                            if (!_threadWatcherActive[threadKey])
                                continue;

                            _threadWatcherCycles[processName][threadName]++;

                            Logger.WriteVerbose($"Thread watcher: {processName} -> {threadName} not found (cycle {_threadWatcherCycles[processName][threadName]}/5)", ConsoleColor.Cyan);
                            Logger.WriteLog($"Thread watcher: {processName} -> {threadName} not found (cycle {_threadWatcherCycles[processName][threadName]}/5)");

                            if (_threadWatcherCycles[processName][threadName] >= 5)
                            {
                                Logger.WriteColored($"Thread watcher stopped: {processName} -> {threadName} not found after 5 cycles", ConsoleColor.Cyan);
                                Logger.WriteLog($"Thread watcher stopped: {processName} -> {threadName} not found after 5 cycles");
                                _threadWatcherActive[threadKey] = false;
                                threadsToRemove.Add((processName, threadName));
                            }
                        }
                    }

                    foreach (var (procName, threadName) in threadsToRemove)
                    {
                        var processEntry = _pendingThreads.FirstOrDefault(x =>
                        {
                            try
                            {
                                var p = Process.GetProcessById(x.Key);
                                return p.ProcessName.Equals(procName, StringComparison.OrdinalIgnoreCase);
                            }
                            catch
                            {
                                return false;
                            }
                        });

                        if (processEntry.Key != 0 && _pendingThreads.ContainsKey(processEntry.Key))
                        {
                            string threadKey = $"{processEntry.Key}_{threadName}";
                            _pendingThreads[processEntry.Key].Remove(threadName);
                            _threadWatcherActive.Remove(threadKey);

                            if (_pendingThreads[processEntry.Key].Count == 0)
                            {
                                _pendingThreads.Remove(processEntry.Key);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLog($"Error in CheckMissingThreads: {ex.Message}");
            }
        }

        private static string? GetProcessName(int processId)
        {
            try
            {
                var process = Process.GetProcessById(processId);
                return process.ProcessName;
            }
            catch
            {
                return null;
            }
        }

        private static void CheckForNewSystemProcesses()
        {
            try
            {
                if (!_gameOptimized && !_forceSystemOptimizations)
                {
                    Logger.WriteVerbose("System process check skipped - game not optimized and system optimizations not forced", ConsoleColor.Cyan);
                    return;
                }

                Logger.WriteVerbose("Checking for new system processes...", ConsoleColor.Cyan);
                Logger.WriteLog("Checking for new system processes");

                foreach (var processConfig in ConfigLoader.SystemConfigs)
                {
                    string processName = processConfig.Key;
                    Process[] processes = Process.GetProcessesByName(processName);

                    foreach (Process process in processes)
                    {
                        if (_processedProcesses.Contains(process.Id) || _ignoredSecondaryProcesses.Contains(process.Id))
                            continue;

                        try
                        {
                            Logger.WriteColored($"New system process detected: {processName} (PID {process.Id})", ConsoleColor.Cyan);
                            Logger.WriteLog($"New system process detected: {processName} (PID {process.Id})");

                            ApplyProcessSettings(process, processName, ConfigLoader.SystemConfigs);
                            EnumerateProcessThreads(process, processName, ConfigLoader.SystemConfigs, false);

                            _processedProcesses.Add(process.Id);

                            process.EnableRaisingEvents = true;
                            process.Exited += (sender, e) =>
                            {
                                Logger.WriteColored($"System process {processName} (PID {process.Id}) exited.", ConsoleColor.Cyan);
                                Logger.WriteLog($"System process {processName} (PID {process.Id}) exited.");
                                CleanupProcessData(process.Id);
                                _processedProcesses.Remove(process.Id);
                                process.Dispose();
                            };
                        }
                        catch (Exception ex)
                        {
                            Logger.WriteColored($"Error processing new system process {processName}: {ex.Message}", ConsoleColor.Cyan);
                            Logger.WriteLog($"Error processing new system process {processName}: {ex.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.WriteColored($"Error checking for new system processes: {ex.Message}", ConsoleColor.Cyan);
                Logger.WriteLog($"Error checking for new system processes: {ex.Message}");
            }
        }

        private static void CleanupThreadOperationTracking()
        {
            try
            {
                var now = DateTime.Now;
                var threadsToRemove = new List<int>();

                foreach (var kvp in _lastThreadOperationTime)
                {
                    if ((now - kvp.Value).TotalMinutes > 1)
                    {
                        threadsToRemove.Add(kvp.Key);
                    }
                }

                foreach (var threadId in threadsToRemove)
                {
                    _lastThreadOperationTime.Remove(threadId);
                    _threadSuspendCounts.Remove(threadId);
                    _kernelModeFailedThreads.Remove(threadId);  // Clean up kernel mode failed threads cache
                }
            }
            catch { }
        }

        private static void CheckForThreadReverts()
        {
            try
            {
                var processesToCheck = new List<int>();

                lock (_processedProcesses)
                {
                    processesToCheck.AddRange(_processedProcesses);
                }

                foreach (int processId in processesToCheck)
                {
                    try
                    {
                        Process process = Process.GetProcessById(processId);
                        if (process.HasExited)
                        {
                            CleanupProcessData(processId);
                            continue;
                        }
                    }
                    catch (ArgumentException)
                    {
                        CleanupProcessData(processId);
                    }
                }

                // DWM thread optimizations now applied once at game detection (see above)
            }
            catch (Exception ex)
            {
                Logger.WriteLog($"Error in CheckForThreadReverts: {ex.Message}");
            }
        }

        private static void CheckPendingThreads()
        {
            try
            {
                var processesToCheck = new List<int>();

                lock (_pendingThreads)
                {
                    processesToCheck.AddRange(_pendingThreads.Keys);
                }

                foreach (int processId in processesToCheck)
                {
                    try
                    {
                        Process process = Process.GetProcessById(processId);
                        if (process.HasExited)
                        {
                            lock (_pendingThreads)
                            {
                                _pendingThreads.Remove(processId);
                            }
                            continue;
                        }

                        string processName = process.ProcessName;
                        Dictionary<string, ProcessConfig>? configs = null;

                        if (ConfigLoader.GameConfigs.ContainsKey(processName))
                            configs = ConfigLoader.GameConfigs;
                        else if (ConfigLoader.SystemConfigs.ContainsKey(processName))
                            configs = ConfigLoader.SystemConfigs;
                        else
                            continue;

                        if (!configs.TryGetValue(processName, out ProcessConfig? processConfig))
                            continue;

                        HashSet<string>? pendingThreads;
                        lock (_pendingThreads)
                        {
                            if (!_pendingThreads.TryGetValue(processId, out pendingThreads))
                                continue;
                        }

                        var foundThreads = new List<string>();

                        foreach (ProcessThread thread in process.Threads)
                        {
                            try
                            {
                                string threadName = GetThreadName(thread.Id);
                                string threadIdKey = thread.Id.ToString();
                                bool nameMatch = !string.IsNullOrEmpty(threadName) && pendingThreads!.Contains(threadName);
                                bool idMatch = pendingThreads!.Contains(threadIdKey);

                                if (nameMatch || idMatch)
                                {
                                    string configKey = nameMatch ? threadName : threadIdKey;
                                    if (processConfig!.Threads.TryGetValue(configKey, out ThreadConfig? config))
                                    {
                                        ApplyConfiguredThreadSettings(thread.Id, threadName, processId, configKey, config);
                                    }

                                    foundThreads.Add(configKey);
                                }
                            }
                            catch { }
                        }

                        if (foundThreads.Count > 0)
                        {
                            foreach (string foundThread in foundThreads)
                            {
                                string threadKey = $"{processId}_{foundThread}";
                                _threadWatcherActive.Remove(threadKey);

                                if (_threadWatcherCycles.ContainsKey(processName) &&
                                    _threadWatcherCycles[processName].ContainsKey(foundThread))
                                {
                                    _threadWatcherCycles[processName].Remove(foundThread);
                                }
                            }

                            Logger.WriteVerbose($"Thread watcher reset: {foundThreads.Count} threads found in {processName}", ConsoleColor.Cyan);
                            Logger.WriteLog($"Thread watcher reset: {foundThreads.Count} threads found in {processName}");
                        }

                        if (foundThreads.Count > 0)
                        {
                            lock (_pendingThreads)
                            {
                                if (_pendingThreads.TryGetValue(processId, out var currentPending))
                                {
                                    currentPending!.ExceptWith(foundThreads);
                                    if (currentPending.Count == 0)
                                    {
                                        _pendingThreads.Remove(processId);
                                    }
                                }
                            }
                        }
                    }
                    catch (ArgumentException)
                    {
                        lock (_pendingThreads)
                        {
                            _pendingThreads.Remove(processId);
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private static void CheckForConfiguredProcesses()
        {
            bool processedGameThisLoop = CheckProcesses(ConfigLoader.GameConfigs, true);

            if (processedGameThisLoop && !_gameOptimized)
            {
                _gameOptimized = true;
                _autoCapsAppliedThisGameSession = false;

                try
                {
                    DARKSTAR.Features.AutoIdleManager.EnableForGameSession();
                }
                catch (Exception ex)
                {
                    Logger.WriteColored($"[AUTO-IDLE] ERROR enabling idle prevention: {ex.Message}", ConsoleColor.Cyan);
                    Logger.WriteLog($"[AUTO-IDLE] ERROR enabling idle prevention: {ex.Message}");
                }
                
                // FIXED: Apply network throttling when game is detected
                if (ConfigLoader.NetworkThrottleEnabled)
                {
                    try
                    {
                        IntPtr backgroundAffinity = AffinityParser.Parse("e-core");
                        if (backgroundAffinity == IntPtr.Zero)
                            backgroundAffinity = AffinityParser.Parse("ALL");
                        Features.NetworkThrottler.Apply(backgroundAffinity);
                        Logger.WriteVerbose("Network throttling applied for background processes", ConsoleColor.Cyan);
                        Logger.WriteLog("Network throttling applied for background processes");
                    }
                    catch (Exception ex)
                    {
                        Logger.WriteLog($"[NETWORK] ERROR applying throttle: {ex.Message}");
                    }
                }
                
                // Apply system process optimizations (csrss, dwm)
                try
                {
                    Features.SystemProcessOptimizer.ApplyGamingOptimizations();
                }
                catch (Exception ex)
                {
                    Logger.WriteLog($"[SYS-OPT] ERROR applying optimizations: {ex.Message}");
                }

                // Apply DWM thread-level optimizations (CMit/CKst high, rest demoted)
                try
                {
                    Features.DwmOptimizer.ApplyOneTimeThreadOptimizations();
                }
                catch (Exception ex)
                {
                    Logger.WriteLog($"[DWM] ERROR applying thread optimizations: {ex.Message}");
                }

                Logger.WriteMinimal("⚡ GAME OPTIMIZATION ACTIVATED", ConsoleColor.Cyan);
                Logger.WriteLog("GAME OPTIMIZATION ACTIVATED - System process monitoring now enabled");
            }

            if (_gameOptimized && !_autoCapsAppliedThisGameSession)
            {
                TryAutoApplyMemoryCapsOnGameLaunch();
                _autoCapsAppliedThisGameSession = true;
            }

            if (_gameOptimized || _forceSystemOptimizations)
            {
                CheckProcesses(ConfigLoader.SystemConfigs, false);
            }
        }

        /// <summary>
        /// Non-blocking check for pending game initializations.
        /// Called from the monitoring loop to process games that have waited 10 seconds.
        /// </summary>
        private static void CheckPendingGameInitializations()
        {
            List<int> completedInits = new List<int>();
            
            lock (_pendingGameInitLock)
            {
                if (_pendingGameInit.Count == 0)
                    return;
                    
                var now = DateTime.Now;
                
                foreach (var kvp in _pendingGameInit)
                {
                    int processId = kvp.Key;
                    var (process, processName, configs, initTime) = kvp.Value;
                    
                    // Wait 10 seconds before applying optimizations
                    if ((now - initTime).TotalSeconds < 10)
                        continue;
                    
                    try
                    {
                        if (process.HasExited)
                        {
                            Logger.WriteColored($"Game process {processName} exited during initialization wait.", ConsoleColor.Cyan);
                            Logger.WriteLog($"Game process {processName} exited during initialization wait.");
                            completedInits.Add(processId);
                            continue;
                        }
                        
                        Logger.WriteVerbose($"Applying optimizations to {processName} after 10-second wait...", ConsoleColor.Cyan);
                        Logger.WriteLog($"Applying optimizations to {processName} after 10-second wait...");
                        
                        // Now apply the actual optimizations
                        ApplyProcessSettings(process, processName, configs);
                        EnumerateProcessThreads(process, processName, configs, true);
                        
                        lock (_threadMonitoringCyclesLock)
                        {
                            _threadMonitoringCycles[processId] = 0;
                        }
                        
                        Logger.WriteMinimal($"✓ {processName} optimized", ConsoleColor.Cyan);
                        Logger.WriteLog("Thread optimization applied.");
                        
                        completedInits.Add(processId);
                    }
                    catch (Exception ex)
                    {
                        Logger.WriteColored($"ERROR: Processing pending game {processName} (PID {processId}): {ex.Message}", ConsoleColor.Cyan);
                        Logger.WriteLog($"ERROR: Processing pending game {processName} (PID {processId}): {ex.Message}");
                        completedInits.Add(processId); // Remove from pending to avoid retry loop
                    }
                }
                
                // Remove completed initializations
                foreach (int processId in completedInits)
                {
                    _pendingGameInit.Remove(processId);
                }
            }
        }

        private static bool CheckProcesses(Dictionary<string, ProcessConfig> configs, bool isGame)
        {
            bool anyProcessed = false;

            foreach (string processName in configs.Keys)
            {
                Process[] processes = Process.GetProcessesByName(processName);
                if (processes.Length == 0) continue;

                Process? targetProcess = null;

                if (processes.Length > 1)
                {
                    if (isGame && _gameProcessId != -1)
                    {
                        targetProcess = processes.FirstOrDefault(p => p.Id == _gameProcessId);
                    }

                    if (targetProcess == null)
                    {
                        if (configs.TryGetValue(processName, out ProcessConfig? config))
                        {
                            targetProcess = IdentifyMainProcess(processes, config!);

                            if (targetProcess != null)
                            {
                                foreach (var p in processes)
                                {
                                    if (p.Id != targetProcess.Id && !_ignoredSecondaryProcesses.Contains(p.Id))
                                    {
                                        _ignoredSecondaryProcesses.Add(p.Id);
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    targetProcess = processes[0];
                }

                if (targetProcess == null) continue;

                try
                {
                    if (_processedProcesses.Contains(targetProcess.Id))
                    {
                        continue;
                    }

                    string type = isGame ? "Game" : "System";
                    Logger.WriteColored($"\n{type} MAIN process detected: {processName} (PID {targetProcess.Id}) at {DateTime.Now:HH:mm:ss}", ConsoleColor.Cyan);
                    Logger.WriteLog($"{type} MAIN process detected: {processName} (PID {targetProcess.Id})");

                    if (isGame)
                    {
                        _gameProcessId = targetProcess.Id;

                        // NON-BLOCKING: Queue game for initialization after 10 seconds
                        // This allows the monitoring loop to continue running
                        Logger.WriteVerbose("Queuing game for initialization in 10 seconds (non-blocking)...", ConsoleColor.Cyan);
                        Logger.WriteLog("Queuing game for initialization in 10 seconds (non-blocking)...");
                        
                        lock (_pendingGameInitLock)
                        {
                            _pendingGameInit[targetProcess.Id] = (targetProcess, processName, configs, DateTime.Now);
                        }
                        
                        // Mark as processed immediately to prevent re-detection
                        _processedProcesses.Add(targetProcess.Id);
                        anyProcessed = true;
                        
                        // Set up exit handler now
                        targetProcess.EnableRaisingEvents = true;
                        targetProcess.Exited += (sender, e) =>
                        {
                            Logger.WriteMinimal($"⊘ {processName} exited", ConsoleColor.Cyan);
                            Logger.WriteLog($"{type} process {processName} (PID {targetProcess.Id}) exited.");
                            
                            // Remove from pending if still there
                            lock (_pendingGameInitLock)
                            {
                                _pendingGameInit.Remove(targetProcess.Id);
                            }
                            
                            CleanupProcessData(targetProcess.Id);
                            _processedProcesses.Remove(targetProcess.Id);
                            targetProcess.Dispose();
                            
                            _gameOptimized = false;
                            _gameProcessId = -1;
                            _autoCapsAppliedThisGameSession = false;

                            try
                            {
                                DARKSTAR.Features.AutoIdleManager.RestoreAfterGameSession();
                            }
                            catch (Exception ex)
                            {
                                Logger.WriteColored($"[AUTO-IDLE] ERROR restoring idle: {ex.Message}", ConsoleColor.Cyan);
                                Logger.WriteLog($"[AUTO-IDLE] ERROR restoring idle: {ex.Message}");
                            }
                            
                            // Restore network throttling when game exits
                            Features.NetworkThrottler.Restore();
                            
                            // Restore system process priorities (csrss, dwm)
                            try
                            {
                                Features.SystemProcessOptimizer.RestoreOriginalPriorities();
                            }
                            catch (Exception ex)
                            {
                                Logger.WriteLog($"[SYS-OPT] ERROR restoring priorities: {ex.Message}");
                            }

                            Logger.WriteMinimal("⊘ GAME OPTIMIZATION DEACTIVATED", ConsoleColor.Cyan);
                            Logger.WriteLog("GAME OPTIMIZATION DEACTIVATED - System process monitoring paused");
                        };
                        
                        continue; // Don't apply settings yet, wait for initialization period
                    }

                    ApplyProcessSettings(targetProcess, processName, configs);
                    EnumerateProcessThreads(targetProcess, processName, configs, isGame);

                    Logger.WriteMinimal($"✓ {processName} optimized", ConsoleColor.Cyan);
                    Logger.WriteLog("Thread optimization applied.");
                    _processedProcesses.Add(targetProcess.Id);
                    anyProcessed = true;

                    lock (_threadMonitoringCyclesLock)
                    {
                        _threadMonitoringCycles[targetProcess.Id] = 0;
                    }

                    targetProcess.EnableRaisingEvents = true;
                    targetProcess.Exited += (sender, e) =>
                    {
                        Logger.WriteMinimal($"⊘ {processName} exited", ConsoleColor.Cyan);
                        Logger.WriteLog($"{type} process {processName} (PID {targetProcess.Id}) exited.");
                        CleanupProcessData(targetProcess.Id);
                        _processedProcesses.Remove(targetProcess.Id);
                        targetProcess.Dispose();
                    };
                }
                catch (Exception ex)
                {
                    Logger.WriteColored($"ERROR: Processing {processName} (PID {targetProcess.Id}): {ex.Message}", ConsoleColor.Cyan);
                    Logger.WriteLog($"ERROR: Processing {processName} (PID {targetProcess.Id}): {ex.Message}");
                }
            }

            return anyProcessed;
        }

        private static void ApplyProcessSettings(Process process, string processName, Dictionary<string, ProcessConfig> configs)
        {
            try
            {
                if (!configs.TryGetValue(processName, out ProcessConfig? processConfig))
                    return;

                IntPtr processHandle = OpenProcess(PROCESS_SET_INFORMATION, false, (uint)process.Id);
                if (processHandle == IntPtr.Zero)
                    return;

                try
                {
                    if (processConfig!.Priority != 0)
                    {
                        uint priorityClass = ConvertToPriorityClass(processConfig.Priority);
                        SetPriorityClass(processHandle, priorityClass);
                    }

                    if (processConfig.Affinity != "ALL")
                    {
                        IntPtr affinity = AffinityParser.Parse(processConfig.Affinity);
                        SetProcessAffinityMask(processHandle, affinity);
                    }

                    if (processConfig.GpuPriority != Features.GpuPriority.None)
                    {
                        Features.GpuPriorityManager.SetGpuPriority(process, processConfig.GpuPriority);
                    }

                    bool shouldDisableBoost = (processConfig.DisableBoost ||
                                             ConfigLoader.DisableBoostProcesses.Contains(process.ProcessName)) &&
                                             !_disableBoostApplied.Contains(process.Id);

                    if (shouldDisableBoost && (processConfig.Priority != 0 || processConfig.Affinity != "ALL"))
                    {
                        SetProcessPriorityBoost(processHandle, true);
                        _disableBoostApplied.Add(process.Id);
                        Logger.WriteVerbose($"Disabled priority boost for: {process.ProcessName}", ConsoleColor.DarkCyan);
                        Logger.WriteLog($"Disabled priority boost for: {process.ProcessName}");
                    }
                }
                finally
                {
                    CloseHandle(processHandle);
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLog($"Error applying process settings for {processName}: {ex.Message}");
            }
        }

        private static void EnumerateProcessThreads(Process process, string processName, Dictionary<string, ProcessConfig> configs, bool isGame)
        {
            try
            {
                if (!configs.TryGetValue(processName, out ProcessConfig? processConfig))
                    return;

                ProcessThreadCollection threads = process.Threads;

                Logger.WriteVerbose($"Total threads found: {threads.Count}", ConsoleColor.Cyan);
                Logger.WriteLog($"Total threads found: {threads.Count} for {processName}");

                int modifiedThreads = 0;
                HashSet<string> foundThreads = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                HashSet<string> configuredThreads = new HashSet<string>(processConfig!.Threads.Keys, StringComparer.OrdinalIgnoreCase);

                foreach (ProcessThread thread in threads.Cast<ProcessThread>())
                {
                    try
                    {
                        bool? wasModified = DisplayThreadInfo(thread, process.Id, processConfig.Threads, foundThreads);
                        if (wasModified.HasValue && wasModified.Value)
                            modifiedThreads++;
                    }
                    catch (Exception ex) when (ex is Win32Exception || ex is InvalidOperationException)
                    {
                    }
                }

                var missingThreads = configuredThreads.Except(foundThreads, StringComparer.OrdinalIgnoreCase).ToList();
                if (missingThreads.Any())
                {
                    Logger.WriteVerbose($"Some configured threads not found initially ({missingThreads.Count}). Will keep watching for them.", ConsoleColor.Cyan);
                    Logger.WriteLog($"Some configured threads not found initially ({missingThreads.Count}) for {processName}");

                    lock (_pendingThreads)
                    {
                        _pendingThreads[process.Id] = new HashSet<string>(missingThreads, StringComparer.OrdinalIgnoreCase);
                    }

                    _threadMonitoringCycles[process.Id] = 0;
                }

                if (isGame)
                {
                    ApplyIntelligentThreadOptimizations(process, processName, processConfig, configuredThreads);
                }

                Logger.WriteVerbose($"Summary: Modified {modifiedThreads} threads, {missingThreads.Count} pending", ConsoleColor.Cyan);
                Logger.WriteLog($"Summary for {processName}: Modified {modifiedThreads} threads, {missingThreads.Count} pending");
            }
            catch (Exception ex)
            {
                Logger.WriteColored($"ERROR: Failed to enumerate threads for {processName}: {ex.Message}", ConsoleColor.Cyan);
                Logger.WriteLog($"ERROR: Failed to enumerate threads for {processName}: {ex.Message}");
            }
        }

        private static bool? DisplayThreadInfo(ProcessThread thread, int processId, Dictionary<string, ThreadConfig> threadConfigs, HashSet<string> processedThreadNames)
        {
            int threadId = thread.Id;
            string threadName = GetThreadName(threadId);

            ThreadConfig? config = null;
            string? configKey = null;

            if (IsValidThreadName(threadName) && threadConfigs.TryGetValue(threadName, out config))
            {
                configKey = threadName;
            }
            else
            {
                string idKey = threadId.ToString();
                if (threadConfigs.TryGetValue(idKey, out config))
                {
                    configKey = idKey;
                }
            }

            if (config == null || string.IsNullOrWhiteSpace(configKey))
                return null;

            processedThreadNames.Add(configKey);
            return ApplyConfiguredThreadSettings(threadId, threadName, processId, configKey, config);
        }

        private static void ApplyIntelligentThreadOptimizations(Process process, string processName, ProcessConfig processConfig, HashSet<string> configuredThreads)
        {
            var detectedThreads = IntelligentThreadDetector.DetectGameThreads(process.Id, processName);
            if (detectedThreads.Count == 0)
                return;

            string summary = IntelligentThreadDetector.GenerateThreadSummary(detectedThreads);
            Logger.WriteMinimal(summary, ConsoleColor.Cyan);
            Logger.WriteLog(summary);

            if (!CpuTopologyDetector.IsDetected)
            {
                CpuTopologyDetector.Detect();
            }

            IntPtr pCoreAffinity = AffinityParser.Parse("p-core");
            if (pCoreAffinity == IntPtr.Zero)
                pCoreAffinity = AffinityParser.Parse("ALL");

            IntPtr eCoreAffinity = CpuTopologyDetector.ECores.Count > 0
                ? AffinityParser.Parse("e-core")
                : AffinityParser.Parse("ALL");

            int updated = 0;
            int skippedConfigured = 0;
            int mainCount = 0;
            int renderCount = 0;
            int workerCount = 0;
            int networkCount = 0;

            foreach (var thread in detectedThreads)
            {
                bool isMain = thread.IsMainThread || thread.Type == IntelligentThreadDetector.ThreadType.Main;
                bool isRender = thread.Type == IntelligentThreadDetector.ThreadType.Render;
                bool isWorker = thread.Type == IntelligentThreadDetector.ThreadType.Worker;
                bool isNetwork = thread.Type == IntelligentThreadDetector.ThreadType.Network;

                if (!isMain && !isRender && !isWorker && !isNetwork)
                    continue;

                string? threadName = thread.Description;
                if (string.IsNullOrWhiteSpace(threadName))
                {
                    threadName = GetThreadName(thread.ThreadId);
                }

                if (!string.IsNullOrWhiteSpace(threadName) && configuredThreads.Contains(threadName))
                {
                    skippedConfigured++;
                    continue;
                }

                int targetPriority;
                IntPtr targetAffinity;

                if (isMain)
                {
                    targetPriority = THREAD_PRIORITY_HIGH_VALUE;
                    targetAffinity = pCoreAffinity;
                    mainCount++;
                }
                else if (isRender)
                {
                    targetPriority = THREAD_PRIORITY_ABOVE_NORMAL_VALUE;
                    targetAffinity = pCoreAffinity;
                    renderCount++;
                }
                else if (isNetwork)
                {
                    targetPriority = THREAD_PRIORITY_BELOW_NORMAL_VALUE;
                    targetAffinity = eCoreAffinity;
                    networkCount++;
                }
                else
                {
                    targetPriority = THREAD_PRIORITY_BELOW_NORMAL_VALUE;
                    targetAffinity = eCoreAffinity;
                    workerCount++;
                }

                if (ApplyThreadSettings(thread.ThreadId, targetPriority, targetAffinity, processConfig.DisableBoost))
                {
                    updated++;
                }
            }

            string appliedSummary = $"Thread detector applied: Main {mainCount}, Render {renderCount}, Worker {workerCount}, Network {networkCount}, Updated {updated}, Skipped {skippedConfigured}";
            Logger.WriteMinimal(appliedSummary, ConsoleColor.Cyan);
            Logger.WriteLog(appliedSummary);
        }

        private static bool ApplyThreadSettings(int threadId, int priority, IntPtr affinity, bool disableBoost)
        {
            // Try kernel mode first if available
            if (ConfigLoader.UseKernelDriver && KernelDriverInterface.IsAvailable)
            {
                bool kernelSuccess = true;
                
                if (!KernelDriverInterface.SetThreadPriority(threadId, priority))
                {
                    kernelSuccess = false;
                }
                
                if (affinity != IntPtr.Zero && !KernelDriverInterface.SetThreadAffinity(threadId, affinity))
                {
                    kernelSuccess = false;
                }
                
                if (kernelSuccess)
                {
                    return true;
                }
                
                // Cache failure to avoid repeated kernel mode attempts
                // Note: This cache is cleaned up periodically in CleanupThreadOperationTracking()
                if (_kernelModeFailedThreads.Add(threadId))
                {
                    Logger.WriteVerbose($"Kernel mode failed for thread {threadId}, falling back to user-mode", ConsoleColor.Yellow);
                }
                // Fall through to user-mode as it may still succeed
            }
            
            // Existing user-mode implementation
            IntPtr threadHandle = OpenThread(THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, false, (uint)threadId);
            if (threadHandle == IntPtr.Zero)
                return false;

            try
            {
                bool prioritySet = SetThreadPriority(threadHandle, priority);
                bool affinitySet = true;
                bool boostSet = true;
                if (affinity != IntPtr.Zero)
                {
                    affinitySet = TrySetThreadAffinity(threadHandle, affinity, threadId);
                }

                if (disableBoost)
                {
                    boostSet = SetThreadPriorityBoost(threadHandle, true);
                }

                if (!prioritySet)
                {
                    int error = Marshal.GetLastWin32Error();
                    Logger.WriteVerbose($"[THREAD] Failed to set priority {priority} for TID {threadId} (error {error}).", ConsoleColor.Cyan);
                    Logger.WriteLog($"[THREAD] Failed to set priority {priority} for TID {threadId} (error {error}).");
                }

                return prioritySet && affinitySet && boostSet;
            }
            finally
            {
                CloseHandle(threadHandle);
            }
        }

        private static bool ApplyConfiguredThreadSettings(int threadId, string threadName, int processId, string configKey, ThreadConfig config)
        {
            if (!IsThreadPrioritySupported(config.Priority))
            {
                string supported = $"Supported: {string.Join(", ", SupportedThreadPriorities)}";
                Logger.WriteColored($"[THREAD] Unsupported priority {config.Priority} for {configKey} (PID {processId}, TID {threadId}). {supported}.", ConsoleColor.Cyan);
                Logger.WriteLog($"[THREAD] Unsupported priority {config.Priority} for {configKey} (PID {processId}, TID {threadId}). {supported}.");
                return false;
            }

            string affinityText = string.IsNullOrWhiteSpace(config.Affinity) ? "ALL" : config.Affinity;
            IntPtr affinity = AffinityParser.Parse(affinityText);

            bool applied = ApplyThreadSettings(threadId, config.Priority, affinity, config.DisableBoost);
            string nameLabel = IsValidThreadName(threadName) ? threadName : configKey;

            if (applied)
            {
                Logger.WriteVerbose($"[THREAD] Applied: {nameLabel} (PID {processId}, TID {threadId}) -> Prio {config.Priority}, Aff {affinityText}, Boost {!config.DisableBoost}", ConsoleColor.DarkCyan);
                Logger.WriteLog($"[THREAD] Applied: {nameLabel} (PID {processId}, TID {threadId}) -> Prio {config.Priority}, Aff {affinityText}, Boost {!config.DisableBoost}");
            }
            else
            {
                Logger.WriteColored($"[THREAD] Failed to apply: {nameLabel} (PID {processId}, TID {threadId}).", ConsoleColor.Cyan);
                Logger.WriteLog($"[THREAD] Failed to apply: {nameLabel} (PID {processId}, TID {threadId}).");
            }

            return applied;
        }

        private static readonly HashSet<int> SupportedThreadPriorities = new HashSet<int> { 15, 2, 1, 0, -1, -2, -15 };
        private static readonly string[] InvalidThreadNames = { "N/A", "NO_NAME", "EMPTY", "NO_ACCESS" };

        private static bool IsThreadPrioritySupported(int priority)
        {
            // Thread priority values:
            // 15=THREAD_PRIORITY_TIME_CRITICAL, 2=THREAD_PRIORITY_HIGHEST, 1=THREAD_PRIORITY_ABOVE_NORMAL,
            // 0=THREAD_PRIORITY_NORMAL, -1=THREAD_PRIORITY_BELOW_NORMAL, -2=THREAD_PRIORITY_LOWEST, -15=THREAD_PRIORITY_IDLE
            return SupportedThreadPriorities.Contains(priority);
        }

        private static bool TrySetThreadAffinity(IntPtr threadHandle, IntPtr affinity, int threadId)
        {
            IntPtr previousAffinity = SetThreadAffinityMask(threadHandle, affinity);
            if (previousAffinity == IntPtr.Zero)
            {
                int affinityError = Marshal.GetLastWin32Error();
                Logger.WriteVerbose($"[THREAD] Failed to set affinity for TID {threadId} (error {affinityError}).", ConsoleColor.Cyan);
                Logger.WriteLog($"[THREAD] Failed to set affinity for TID {threadId} (error {affinityError}).");
                return false;
            }

            return true;
        }

        private static bool IsValidThreadName(string? threadName)
        {
            if (string.IsNullOrEmpty(threadName))
                return false;

            if (threadName.StartsWith("N/A", StringComparison.OrdinalIgnoreCase))
                return false;

            return !InvalidThreadNames.Any(name => threadName.Equals(name, StringComparison.OrdinalIgnoreCase));
        }

        private static Process? IdentifyMainProcess(Process[] candidates, ProcessConfig config)
        {
            foreach (var p in candidates)
            {
                if (_ignoredSecondaryProcesses.Contains(p.Id)) continue;

                try
                {
                    p.Refresh();
                    foreach (ProcessThread t in p.Threads)
                    {
                        string tName = GetThreadName(t.Id);
                        if (!string.IsNullOrEmpty(tName) && config.Threads.ContainsKey(tName))
                        {
                            return p;
                        }
                    }
                }
                catch { }
            }
            return null;
        }

        private static void MonitorMemoryCapsForTargetProcesses()
        {
            if (!ConfigLoader.AutoApplyMemoryCapsOnGameLaunch)
                return;

            if (!_gameOptimized && !_forceSystemOptimizations)
                return;

            if (ConfigLoader.AutoMemoryCapsTargets == null || ConfigLoader.AutoMemoryCapsTargets.Count == 0)
                return;

            if (ConfigLoader.MemoryLimitMb == null || ConfigLoader.MemoryLimitMb.Count == 0)
                return;

            foreach (var baseName in ConfigLoader.AutoMemoryCapsTargets.ToList())
            {
                if (string.IsNullOrWhiteSpace(baseName))
                    continue;

                if (!ConfigLoader.MemoryLimitMb.TryGetValue(baseName, out int limitMb) || limitMb <= 0)
                    continue;

                try
                {
                    var processes = Process.GetProcessesByName(baseName);
                    if (processes.Length == 0)
                        continue;

                    ulong limitBytes = (ulong)limitMb * 1024UL * 1024UL;

                    foreach (var proc in processes)
                    {
                        try
                        {
                            if (proc.HasExited)
                                continue;

                            ulong workingSet = (ulong)proc.WorkingSet64;

                            if (workingSet > limitBytes)
                            {
                                Logger.WriteLog($"Memory limit exceeded: {baseName} using {workingSet / (1024 * 1024)} MB (limit: {limitMb} MB). Restarting...");
                                Logger.WriteMinimal($"⚠ {baseName} exceeded {limitMb} MB limit, restarting...", ConsoleColor.Cyan);

                                string? exePath = null;
                                try
                                {
                                    exePath = proc.MainModule?.FileName;
                                }
                                catch { }

                                if (string.IsNullOrWhiteSpace(exePath))
                                {
                                    try
                                    {
                                        exePath = AppPathResolver.ResolveExeFullPath(baseName) ?? AppPathResolver.ResolveExeFullPath(baseName + ".exe");
                                    }
                                    catch { }
                                }

                                if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
                                {
                                    Logger.WriteLog($"Cannot restart {baseName}: executable path not found.");
                                    continue;
                                }

                                try
                                {
                                    proc.Kill(entireProcessTree: true);
                                    proc.WaitForExit(2000);
                                }
                                catch (Exception ex)
                                {
                                    Logger.WriteLog($"Failed to kill {baseName}: {ex.Message}");
                                    continue;
                                }

                                var startInfo = new ProcessStartInfo
                                {
                                    FileName = exePath,
                                    UseShellExecute = false,
                                    WorkingDirectory = Path.GetDirectoryName(exePath) ?? ""
                                };

                                using var limiter = new JobObjectMemoryLimiter(name: $"DARKSTARAutoMemCap_{baseName}");
                                limiter.SetJobMemoryLimitBytes(limitBytes, killOnJobClose: true);
                                limiter.LaunchInJob(startInfo);

                                Logger.WriteLog($"Restarted {baseName} with {limitMb} MB memory cap.");
                                Logger.WriteMinimal($"✓ {baseName} restarted with {limitMb} MB cap", ConsoleColor.Cyan);

                                break;
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.WriteLog($"Error checking memory for {baseName}: {ex.Message}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.WriteLog($"Error monitoring memory caps for {baseName}: {ex.Message}");
                }
            }
        }

        private static void TryAutoApplyMemoryCapsOnGameLaunch()
        {
            if (!ConfigLoader.AutoApplyMemoryCapsOnGameLaunch)
                return;

            if (ConfigLoader.AutoMemoryCapsTargets == null || ConfigLoader.AutoMemoryCapsTargets.Count == 0)
                return;

            if (ConfigLoader.MemoryLimitMb == null || ConfigLoader.MemoryLimitMb.Count == 0)
                return;

            var targets = new List<(string BaseName, int LimitMb)>();
            foreach (var baseName in ConfigLoader.AutoMemoryCapsTargets.ToList())
            {
                if (string.IsNullOrWhiteSpace(baseName))
                    continue;

                if (!ConfigLoader.MemoryLimitMb.TryGetValue(baseName, out int limitMb) || limitMb <= 0)
                    continue;

                targets.Add((baseName, limitMb));
            }

            if (targets.Count == 0)
                return;

            if (ConfigLoader.PromptBeforeAutoMemoryCapsOnGameLaunch)
            {
                string preview = string.Join("\n", targets
                    .OrderBy(t => t.BaseName, StringComparer.OrdinalIgnoreCase)
                    .Take(12)
                    .Select(t => $"- {t.BaseName}.exe  ({t.LimitMb} MB)"));

                if (targets.Count > 12)
                    preview += $"\n- ...and {targets.Count - 12} more";

                var msg =
                    "A game was detected and DARKSTAR is set to auto-apply memory caps.\n\n" +
                    "This will RESTART the following checked apps to apply a hard cap:\n" +
                    preview +
                    "\n\nContinue?";

                var result = MessageBox.Show(msg, "DARKSTAR — Auto Apply Memory Caps", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (result != DialogResult.Yes)
                {
                    Logger.WriteLog("Auto memory caps cancelled by user prompt.");
                    return;
                }
            }

            int restarted = 0;

            foreach (var t in targets)
            {
                string baseName = t.BaseName;
                int limitMb = t.LimitMb;

                try
                {
                    string? exePath = null;
                    try
                    {
                        foreach (var p in Process.GetProcessesByName(baseName))
                        {
                            try
                            {
                                exePath = p.MainModule?.FileName;
                                if (!string.IsNullOrWhiteSpace(exePath) && File.Exists(exePath))
                                    break;
                            }
                            catch
                            {
                            }
                        }
                    }
                    catch
                    {
                    }

                    if (string.IsNullOrWhiteSpace(exePath))
                    {
                        try
                        {
                            exePath = AppPathResolver.ResolveExeFullPath(baseName) ?? AppPathResolver.ResolveExeFullPath(baseName + ".exe");
                        }
                        catch
                        {
                        }
                    }

                    if (string.IsNullOrWhiteSpace(exePath))
                    {
                        try
                        {
                            string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                            string pfx = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
                            string lad = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

                            var chromeCandidates = new[]
                            {
                                Path.Combine(pf,  "Google", "Chrome", "Application", "chrome.exe"),
                                Path.Combine(pfx, "Google", "Chrome", "Application", "chrome.exe"),
                                Path.Combine(lad, "Google", "Chrome", "Application", "chrome.exe"),
                            };

                            foreach (var c in chromeCandidates)
                            {
                                if (File.Exists(c))
                                {
                                    exePath = c;
                                    break;
                                }
                            }
                        }
                        catch
                        {
                        }
                    }

                    if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
                    {
                        Logger.WriteLog($"Auto memory cap skipped for {baseName}: executable path not found.");
                        continue;
                    }

                    try
                    {
                        foreach (var p in Process.GetProcessesByName(baseName))
                        {
                            try { p.Kill(entireProcessTree: true); }
                            catch { }
                        }
                    }
                    catch { }

                    var startInfo = new ProcessStartInfo
                    {
                        FileName = exePath,
                        UseShellExecute = false,
                        WorkingDirectory = Path.GetDirectoryName(exePath) ?? ""
                    };

                    using var limiter = new JobObjectMemoryLimiter(name: $"DARKSTARAutoMemCap_{baseName}");
                    limiter.SetJobMemoryLimitBytes((ulong)limitMb * 1024UL * 1024UL, killOnJobClose: true);
                    limiter.LaunchInJob(startInfo);

                    restarted++;
                    Logger.WriteLog($"Auto memory cap applied: {baseName} restarted with {limitMb} MB job cap.");
                }
                catch (Exception ex)
                {
                    Logger.WriteLog($"Auto memory cap failed for {baseName}: {ex.Message}");
                }
            }

            if (restarted > 0)
            {
                Logger.WriteMinimal($"✓ Auto memory caps applied to {restarted} app(s)", ConsoleColor.Cyan);
                Logger.WriteLog($"Auto memory caps applied to {restarted} app(s).");
            }
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

        private static void CleanupProcessData(int processId)
        {
            lock (_processedProcesses)
            {
                _processedProcesses.Remove(processId);
            }

            lock (_pendingThreads)
            {
                _pendingThreads.Remove(processId);
            }

            lock (_threadPriorityHistory)
            {
                _threadPriorityHistory.Remove(processId);
            }

            // FIXED: Add proper synchronization for these collections
            lock (_threadMonitoringCyclesLock)
            {
                _threadMonitoringCycles.Remove(processId);
            }
            
            lock (_appliedModuleThreadsLock)
            {
                _appliedModuleThreads.Remove(processId);
            }
            
            lock (_disableBoostAppliedLock)
            {
                _disableBoostApplied.Remove(processId);
            }
            
            lock (_pendingGameInitLock)
            {
                _pendingGameInit.Remove(processId);
            }
            
            Features.GpuPriorityManager.RemoveTracking(processId);

            if (processId == _gameProcessId)
                _autoCapsAppliedThisGameSession = false;
        }

        private static uint ConvertToPriorityClass(int priority)
        {
            return priority switch
            {
                15 => REALTIME_PRIORITY_CLASS,
                2 => HIGH_PRIORITY_CLASS,
                1 => ABOVE_NORMAL_PRIORITY_CLASS,
                0 => NORMAL_PRIORITY_CLASS,
                -1 => BELOW_NORMAL_PRIORITY_CLASS,
                -2 => IDLE_PRIORITY_CLASS,
                -15 => IDLE_PRIORITY_CLASS,
                _ => NORMAL_PRIORITY_CLASS
            };
        }

        private static bool EnablePrivilege(string privilegeName)
        {
            IntPtr token = IntPtr.Zero;
            if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token))
                return false;

            LUID luid;
            if (!LookupPrivilegeValue(null, privilegeName, out luid))
            {
                CloseHandle(token);
                return false;
            }

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.Privileges = new LUID_AND_ATTRIBUTES[1];
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            bool result = AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            CloseHandle(token);
            return result;
        }
    }
}
