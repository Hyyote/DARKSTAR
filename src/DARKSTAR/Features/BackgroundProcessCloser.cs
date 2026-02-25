using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Threading;

namespace DARKSTAR.Features
{
    /// <summary>
    /// Closes configured background processes when a game session starts and
    /// prevents them from respawning using an event-driven WMI watcher.
    ///
    /// Win32_ProcessStartTrace fires via ETW (Event Tracing for Windows) when
    /// any process is created — it's kernel-level and truly event-driven, not
    /// polled. This means zero CPU cost when nothing is spawning, and immediate
    /// reaction when something does.
    ///
    /// Explorer.exe is special-cased: Windows auto-restarts it when killed, so
    /// the watcher catches the restart and kills it again. On game exit, we
    /// explicitly restart explorer if we killed it.
    /// </summary>
    public static class BackgroundProcessCloser
    {
        private static bool _enabled = false;
        private static volatile bool _guarding = false;
        private static readonly HashSet<string> _targetProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static ManagementEventWatcher? _processWatcher;
        private static readonly object _watcherLock = new object();

        // Track which processes we actually killed so we can restore them
        private static readonly HashSet<string> _killedProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static bool _killedExplorer = false;

        public static void Configure(bool enabled, IEnumerable<string> processNames)
        {
            _enabled = enabled;
            _targetProcesses.Clear();
            if (_enabled && processNames != null)
            {
                foreach (var name in processNames)
                {
                    var trimmed = name?.Trim();
                    if (!string.IsNullOrEmpty(trimmed))
                        _targetProcesses.Add(trimmed.Replace(".exe", string.Empty, StringComparison.OrdinalIgnoreCase));
                }
            }
        }

        /// <summary>
        /// Close all target processes and start event-driven guarding to prevent respawns.
        /// </summary>
        public static void CloseForGameSession()
        {
            if (!_enabled || _guarding || _targetProcesses.Count == 0)
                return;

            try
            {
                _killedProcesses.Clear();
                _killedExplorer = false;

                // Initial kill pass
                foreach (var procName in _targetProcesses)
                {
                    KillProcess(procName);
                }

                // Start event-driven guard to catch respawns
                StartProcessGuard();

                _guarding = true;
                Core.Logger.WriteVerbose("Background processes closed, respawn guard active", ConsoleColor.Cyan);
            }
            catch (Exception ex)
            {
                Core.Logger.WriteLog($"Failed to close background processes: {ex.Message}");
            }
        }

        /// <summary>
        /// Stop guarding and optionally restart explorer.exe if we killed it.
        /// </summary>
        public static void RestoreAfterGameSession()
        {
            if (!_enabled || !_guarding)
                return;

            try
            {
                StopProcessGuard();
                _guarding = false;

                // Restart explorer.exe if we killed it — the shell won't come back on its own
                // if we kept killing its respawns during the session
                if (_killedExplorer)
                {
                    try
                    {
                        // Check if explorer is already running (it might have been restarted
                        // by Windows between our last kill and guard stop)
                        if (Process.GetProcessesByName("explorer").Length == 0)
                        {
                            Process.Start(new ProcessStartInfo
                            {
                                FileName = System.IO.Path.Combine(
                                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                                    "explorer.exe"),
                                UseShellExecute = false
                            });
                            Core.Logger.WriteVerbose("Explorer.exe restarted after game session", ConsoleColor.Cyan);
                        }
                    }
                    catch (Exception ex)
                    {
                        Core.Logger.WriteLog($"Failed to restart explorer: {ex.Message}");
                    }
                }

                _killedProcesses.Clear();
                _killedExplorer = false;
                Core.Logger.WriteVerbose("Background process guard deactivated", ConsoleColor.Cyan);
            }
            catch (Exception ex)
            {
                Core.Logger.WriteLog($"Failed to restore background processes: {ex.Message}");
            }
        }

        /// <summary>
        /// Start a WMI event watcher for process creation events.
        /// Win32_ProcessStartTrace uses ETW under the hood — it's event-driven,
        /// not polled, and fires immediately when a process is created.
        /// Requires admin (which DARKSTAR already has).
        /// </summary>
        private static void StartProcessGuard()
        {
            lock (_watcherLock)
            {
                if (_processWatcher != null)
                    return;

                try
                {
                    var query = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");
                    _processWatcher = new ManagementEventWatcher(query);
                    _processWatcher.EventArrived += OnProcessCreated;
                    _processWatcher.Start();

                    Core.Logger.WriteVerbose("[GUARD] Process respawn watcher started (ETW)", ConsoleColor.DarkCyan);
                }
                catch (Exception ex)
                {
                    Core.Logger.WriteLog($"[GUARD] Failed to start process watcher: {ex.Message}");
                    _processWatcher?.Dispose();
                    _processWatcher = null;
                }
            }
        }

        private static void StopProcessGuard()
        {
            lock (_watcherLock)
            {
                if (_processWatcher == null)
                    return;

                try
                {
                    _processWatcher.Stop();
                    _processWatcher.Dispose();
                }
                catch { }
                finally
                {
                    _processWatcher = null;
                }

                Core.Logger.WriteVerbose("[GUARD] Process respawn watcher stopped", ConsoleColor.DarkCyan);
            }
        }

        /// <summary>
        /// Event handler for process creation events.
        /// Fires on a WMI threadpool thread — keep it fast.
        /// </summary>
        private static void OnProcessCreated(object sender, EventArrivedEventArgs e)
        {
            if (!_guarding)
                return;

            try
            {
                string processName = e.NewEvent.Properties["ProcessName"]?.Value?.ToString() ?? "";
                string nameNoExt = processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                    ? processName[..^4]
                    : processName;

                if (!_targetProcesses.Contains(nameNoExt))
                    return;

                uint pid = Convert.ToUInt32(e.NewEvent.Properties["ProcessID"].Value);

                // Brief delay to let the process initialize enough to be killable
                Thread.Sleep(50);

                try
                {
                    var process = Process.GetProcessById((int)pid);
                    if (!process.HasExited)
                    {
                        process.Kill();
                        Core.Logger.WriteVerbose($"[GUARD] Killed respawned: {nameNoExt} (PID {pid})", ConsoleColor.DarkCyan);

                        if (nameNoExt.Equals("explorer", StringComparison.OrdinalIgnoreCase))
                            _killedExplorer = true;
                    }
                }
                catch
                {
                    // Process may have already exited or be inaccessible
                }
            }
            catch
            {
                // Swallow WMI event processing errors — don't crash the watcher
            }
        }

        private static void KillProcess(string processName)
        {
            try
            {
                var procs = Process.GetProcessesByName(processName);
                foreach (var proc in procs)
                {
                    try
                    {
                        proc.CloseMainWindow();
                        if (!proc.WaitForExit(2000))
                        {
                            proc.Kill();
                        }
                        _killedProcesses.Add(processName);

                        if (processName.Equals("explorer", StringComparison.OrdinalIgnoreCase))
                            _killedExplorer = true;
                    }
                    catch (Exception ex)
                    {
                        Core.Logger.WriteLog($"Failed to close {processName}: {ex.Message}");
                    }
                    finally
                    {
                        proc.Dispose();
                    }
                }
            }
            catch (Exception ex)
            {
                Core.Logger.WriteLog($"Failed to enumerate {processName}: {ex.Message}");
            }
        }
    }
}
