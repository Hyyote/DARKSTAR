using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using DARKSTAR.Core;
using DARKSTAR.Features;
using DARKSTAR.UI;

namespace DARKSTAR
{
    // ========================================================================
    // REWRITE: Updated for JSON config.
    //
    // KEPT: Game executable prompt — user types one game to actively monitor.
    //       This is the core UX: one game at a time, actively optimized.
    //
    // CHANGED: Error messages reference config.json instead of GCFG files.
    //          Removed GCFG-specific error handling.
    // ========================================================================
    class Program
    {
        #region P/Invoke - Console Control
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool BringWindowToTop(IntPtr hWnd);

        private const int SW_SHOW = 5;
        private const int SW_HIDE = 0;
        #endregion

        #region Main Entry Point
        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            RunConsoleMode();
        }

        private static void RunConsoleMode()
        {
            Logger.Initialize();
            ShowConsole();
            ShowBanner();

            CpuTopologyDetector.Detect();

            try
            {
                ConfigLoader.Load();
            }
            catch (FileNotFoundException ex)
            {
                Logger.WriteColored($"ERROR: {ex.Message}", ConsoleColor.Red, true);
                Logger.WriteLog($"ERROR: {ex.Message}");
                MessageBox.Show(
                    $"Configuration file not found:\n{ex.Message}\n\nPlease ensure config.json exists next to the application.",
                    "DARKSTAR - Missing Configuration",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            catch (InvalidOperationException ex)
            {
                Logger.WriteColored($"ERROR: {ex.Message}", ConsoleColor.Red, true);
                Logger.WriteLog($"ERROR: {ex.Message}");
                MessageBox.Show(
                    $"Invalid configuration:\n{ex.Message}\n\nCheck config.json for syntax errors.",
                    "DARKSTAR - Invalid Configuration",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            // ---- Game selection (kept from original) ----
            string? selectedGame = PromptForGameExecutable();
            if (!string.IsNullOrWhiteSpace(selectedGame))
            {
                EnsureGameConfig(selectedGame);
            }

            if (ConfigLoader.GameConfigs.Count == 0 && ConfigLoader.SystemConfigs.Count == 0)
            {
                Logger.WriteColored("No processes configured. Add games to config.json", ConsoleColor.Yellow, true);
                Logger.WriteLog("No processes configured. Exiting.");
                return;
            }

            Logger.SetMinimalMode(!ConfigLoader.VerboseStartup);

            TrayIconManager.Initialize();

            HotkeyManager.OnToggleConsoleRequested += () => ToggleConsole();
            HotkeyManager.OnToggleVerboseRequested += () => Logger.ToggleVerbose();
            HotkeyManager.OnForceSystemOptimizationsRequested += () => MonitoringEngine.ToggleForceSystemOptimizations();

            Logger.WriteMinimal($"Ready. Monitoring {ConfigLoader.GameConfigs.Count} games, {ConfigLoader.SystemConfigs.Count} background procs", ConsoleColor.Cyan);
            Logger.WriteMinimal($"Hotkeys: CTRL+SHIFT+V=Verbose | CTRL+SHIFT+H=Show/Hide | CTRL+SHIFT+G=Force Optim", ConsoleColor.Cyan);
            Logger.WriteLog($"DARKSTAR v1.0.0 Started - {ConfigLoader.GameConfigs.Count} games, {ConfigLoader.SystemConfigs.Count} background processes");

            if (ConfigLoader.NetworkThrottleEnabled)
            {
                NetworkThrottler.Configure(ConfigLoader.NetworkThrottleEnabled, ConfigLoader.NetworkThrottleProcesses);
                Logger.WriteVerbose("NetworkThrottler enabled", ConsoleColor.Cyan);
            }

            if (ConfigLoader.AutoIdleEnabled)
            {
                AutoIdleManager.Configure(ConfigLoader.AutoIdleEnabled);
                Logger.WriteVerbose("AutoIdleManager enabled", ConsoleColor.Cyan);
            }

            GameWindowGuardManager.Configure(ConfigLoader.WinBlockKeysEnabled, ConfigLoader.BlockNoGamingMonitorMode);
            GameWindowGuardManager.Start();

            MonitoringEngine.Start();

            Application.Run();
        }

        private static void ShowHelp()
        {
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine("  DARKSTAR.exe   # Run runtime monitoring (console + tray)");
            Console.WriteLine();
            Console.WriteLine("Hotkeys:");
            Console.WriteLine("  CTRL+SHIFT+V - Toggle verbose logging");
            Console.WriteLine("  CTRL+SHIFT+H - Show/hide console");
            Console.WriteLine("  CTRL+SHIFT+G - Force system optimizations");
        }
        #endregion

        #region Console Display
        static void ShowConsole()
        {
            var consoleHandle = GetConsoleWindow();
            ShowWindow(consoleHandle, SW_SHOW);
        }

        static void ToggleConsole()
        {
            var consoleHandle = GetConsoleWindow();
            if (consoleHandle == IntPtr.Zero) return;

            if (IsWindowVisible(consoleHandle))
            {
                ShowWindow(consoleHandle, SW_HIDE);
                Logger.WriteLog("Console hidden (hotkey)");
            }
            else
            {
                ShowWindow(consoleHandle, SW_SHOW);
                BringWindowToTop(consoleHandle);
                Logger.WriteLog("Console shown (hotkey)");
            }
        }

        static void ShowBanner()
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("DARKSTAR v1.0.0");
            Console.WriteLine("intelligent game thread optimizer");
            Console.WriteLine("──────────────────────────────────");
            Console.ResetColor();
            Console.WriteLine();
        }

        private static string? PromptForGameExecutable()
        {
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.Write("Game executable to monitor (e.g. MyGame.exe): ");
            Console.ResetColor();

            string? input = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(input))
                return null;

            string trimmed = input.Trim();
            try
            {
                trimmed = Path.GetFileName(trimmed);
            }
            catch (Exception ex)
            {
                Logger.WriteColored($"Invalid executable input: {ex.Message}", ConsoleColor.Yellow, true);
                Logger.WriteLog($"Invalid executable input: {ex.Message}");
                return null;
            }
            if (trimmed.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                trimmed = trimmed[..^4];
            }

            trimmed = trimmed.Trim();
            if (string.IsNullOrWhiteSpace(trimmed))
                return null;

            Logger.WriteMinimal($"Tracking game: {trimmed}.exe", ConsoleColor.Cyan);
            Logger.WriteLog($"User selected game executable: {trimmed}.exe");
            return trimmed;
        }

        private static void EnsureGameConfig(string processName)
        {
            if (ConfigLoader.GameConfigs.ContainsKey(processName))
                return;

            // User typed a game not in config.json — add a runtime entry
            ConfigLoader.GameConfigs[processName] = new ProcessConfig
            {
                Priority = 2,      // HIGHEST
                Affinity = "ALL",
                DisableBoost = true,
                GpuPriority = Features.GpuPriority.High
            };
            Logger.WriteColored($"Added runtime game config for {processName}.exe", ConsoleColor.Cyan, true);
            Logger.WriteLog($"Added runtime game config for {processName}.exe");
        }
        #endregion
    }
}
