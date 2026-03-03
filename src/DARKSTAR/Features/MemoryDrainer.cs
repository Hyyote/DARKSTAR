using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace DARKSTAR.Features
{
    /// <summary>
    /// Drains standby/modified/combined memory lists using md.exe.
    ///
    /// Memory lists in Windows:
    /// ─────────────────────────
    /// Windows maintains several memory lists. The "Standby" list contains pages
    /// that were recently freed but haven't been zeroed yet — they're technically
    /// available but Windows keeps them around for fast reclaim. The "Modified" list
    /// contains dirty pages waiting to be written to the pagefile before becoming
    /// Standby. During gaming, these lists can grow to several GB, and when memory
    /// pressure triggers, Windows must flush them synchronously — causing latency
    /// spikes of 5-50ms.
    ///
    /// By periodically draining these lists during a game session, we keep the
    /// working set lean and avoid sudden flushes during gameplay. md.exe uses
    /// NtSetSystemInformation(SystemMemoryListInformation) which requires
    /// SeProfileSingleProcessPrivilege.
    ///
    /// The drain runs at Idle priority on the last CPU core with background I/O
    /// mode enabled, so it has negligible impact on game performance. Each run
    /// is capped by a timeout to prevent any single drain from taking too long.
    ///
    /// Config:
    ///   memory_drain: true/false
    ///   memory_drain_interval_ms: 5000 (how often to drain, minimum 1000)
    ///   memory_drain_timeout_ms: 4500 (kill md.exe if it takes longer, minimum 500)
    /// </summary>
    public static class MemoryDrainer
    {
        #region P/Invoke

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetPriorityClass(IntPtr hProcess, uint dwPriorityClass);

        private const uint PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000;
        private const uint IDLE_PRIORITY_CLASS = 0x00000040;

        #endregion

        #region State

        private static bool _enabled = false;
        private static volatile bool _running = false;
        private static volatile bool _activeForSession = false;
        private static Thread? _drainThread;
        private static string? _mdExePath;

        private static int _intervalMs = 5000;
        private static int _timeoutMs = 4500;

        #endregion

        /// <summary>
        /// Configure the memory drainer. Call once at startup.
        /// </summary>
        public static void Configure(bool enabled, int intervalMs, int timeoutMs)
        {
            _enabled = enabled;
            _intervalMs = Math.Max(1000, intervalMs);
            _timeoutMs = Math.Max(500, Math.Min(timeoutMs, _intervalMs - 200));

            if (!_enabled)
                return;

            // Locate md.exe next to DARKSTAR.exe
            _mdExePath = ResolveMdExePath();
            if (_mdExePath == null)
            {
                Core.Logger.WriteColored("[MEM-DRAIN] md.exe not found next to DARKSTAR.exe — feature disabled", ConsoleColor.Yellow);
                _enabled = false;
                return;
            }

            Core.Logger.WriteVerbose($"[MEM-DRAIN] Configured: interval={_intervalMs}ms, timeout={_timeoutMs}ms, tool={_mdExePath}", ConsoleColor.Cyan);
        }

        /// <summary>
        /// Start draining for a game session. Called when a game is detected.
        /// </summary>
        public static void StartForGameSession()
        {
            if (!_enabled || _running || _mdExePath == null)
                return;

            _activeForSession = true;
            _running = true;

            _drainThread = new Thread(DrainLoop)
            {
                IsBackground = true,
                Name = "MemoryDrainer",
                Priority = ThreadPriority.Lowest
            };
            _drainThread.Start();

            Core.Logger.WriteVerbose("[MEM-DRAIN] Started for game session", ConsoleColor.Green);
        }

        /// <summary>
        /// Stop draining when the game exits.
        /// </summary>
        public static void StopAfterGameSession()
        {
            if (!_activeForSession)
                return;

            _running = false;
            _activeForSession = false;

            // Don't join the thread — it's background and will stop on its own
            Core.Logger.WriteVerbose("[MEM-DRAIN] Stopped after game session", ConsoleColor.Cyan);
        }

        #region Core Loop

        private static void DrainLoop()
        {
            var sw = Stopwatch.StartNew();
            long nextRunMs = 0;

            while (_running)
            {
                nextRunMs += _intervalMs;

                try
                {
                    RunDrain();
                }
                catch (Exception ex)
                {
                    Core.Logger.WriteLog($"[MEM-DRAIN] Error: {ex.Message}");
                }

                // Sleep until next interval, accounting for drain duration
                long remaining = nextRunMs - sw.ElapsedMilliseconds;
                if (remaining > 0)
                {
                    Thread.Sleep((int)remaining);
                }
                else
                {
                    // Drain took longer than interval — reset to avoid drift
                    nextRunMs = sw.ElapsedMilliseconds;
                }
            }
        }

        private static void RunDrain()
        {
            if (_mdExePath == null)
                return;

            Process? proc = null;
            try
            {
                // Launch md.exe -all through cmd.exe with output redirected to nul
                // This matches the original md-loop.ps1 behavior
                string cmdPath = Environment.GetEnvironmentVariable("ComSpec")
                    ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "cmd.exe");

                var psi = new ProcessStartInfo
                {
                    FileName = cmdPath,
                    Arguments = $"/d /c \"\"{_mdExePath}\" -all\" 1>nul 2>nul",
                    WorkingDirectory = Path.GetDirectoryName(_mdExePath) ?? AppContext.BaseDirectory,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                proc = new Process { StartInfo = psi };
                if (!proc.Start())
                    return;

                // Set to Idle priority
                try
                {
                    proc.PriorityClass = ProcessPriorityClass.Idle;
                }
                catch { }

                // Enable background mode (lowers I/O priority)
                try
                {
                    SetPriorityClass(proc.Handle, PROCESS_MODE_BACKGROUND_BEGIN);
                }
                catch { }

                // Pin to last core
                try
                {
                    int cpuCount = Environment.ProcessorCount;
                    if (cpuCount >= 2 && cpuCount <= 63)
                    {
                        proc.ProcessorAffinity = (IntPtr)(1L << (cpuCount - 1));
                    }
                }
                catch { }

                // Wait with timeout
                if (!proc.WaitForExit(_timeoutMs))
                {
                    try { proc.Kill(); } catch { }
                    try { proc.WaitForExit(500); } catch { }
                }
            }
            catch (Exception ex)
            {
                Core.Logger.WriteLog($"[MEM-DRAIN] Launch error: {ex.Message}");
            }
            finally
            {
                proc?.Dispose();
            }
        }

        #endregion

        #region Path Resolution

        private static string? ResolveMdExePath()
        {
            // Check next to DARKSTAR.exe first
            string baseDir = AppContext.BaseDirectory;
            string candidate = Path.Combine(baseDir, "md.exe");
            if (File.Exists(candidate))
                return candidate;

            // Check working directory
            candidate = Path.Combine(Directory.GetCurrentDirectory(), "md.exe");
            if (File.Exists(candidate))
                return candidate;

            // Check config directory
            string configDir = Core.ConfigLoader.ResolvedConfigDir;
            if (!string.IsNullOrWhiteSpace(configDir))
            {
                candidate = Path.Combine(configDir, "md.exe");
                if (File.Exists(candidate))
                    return candidate;
            }

            return null;
        }

        #endregion
    }
}
