using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using DARKSTAR.Core;
using DARKSTAR.Features;
using DARKSTAR.UI;

namespace DARKSTAR
{
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
                Logger.WriteColored($"ERROR: Configuration file not found: {ex.Message}", ConsoleColor.Cyan, true);
                Logger.WriteLog($"ERROR: Configuration file not found: {ex.Message}");
                MessageBox.Show($"Configuration file not found: {ex.Message}\n\nPlease ensure both config\\GAME_PRIORITY.GCFG and config\\PROC_PRIORITY.GCFG exist next to the application.",
                              "DARKSTAR - Missing Configuration", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (ConfigLoader.GameConfigs.Count == 0 && ConfigLoader.SystemConfigs.Count == 0)
            {
                Logger.WriteColored("No processes configured. Exiting.", ConsoleColor.Cyan, true);
                Logger.WriteColored("Run 'DARKSTAR.exe config' to configure processes.", ConsoleColor.Cyan, true);
                Logger.WriteLog("No processes configured. Exiting.");
                return;
            }

            Logger.SetMinimalMode(!ConfigLoader.VerboseStartup);

            TrayIconManager.Initialize();

            HotkeyManager.OnToggleConsoleRequested += () =>
            {
                ToggleConsole();
            };

            HotkeyManager.OnToggleVerboseRequested += () =>
            {
                Logger.ToggleVerbose();
            };

            HotkeyManager.OnForceSystemOptimizationsRequested += () =>
            {
                MonitoringEngine.ToggleForceSystemOptimizations();
            };

            Logger.WriteMinimal($"Ready. Monitoring {ConfigLoader.GameConfigs.Count} games, {ConfigLoader.SystemConfigs.Count} system procs", ConsoleColor.Cyan);
            Logger.WriteMinimal($"Status: Watchers RUNNING | Hotkeys: CTRL+SHIFT+V=Verbose | CTRL+SHIFT+H=Show/Hide | CTRL+SHIFT+G=Force Optim", ConsoleColor.Cyan);
            Logger.WriteLog($"DARKSTAR v1.0.0 Started - Monitoring {ConfigLoader.GameConfigs.Count} game processes, {ConfigLoader.SystemConfigs.Count} system processes");


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
            if (consoleHandle == IntPtr.Zero)
                return;

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
            Console.WriteLine("╔═══════════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║                        DARKSTAR v1.0.0                            ║");
            Console.WriteLine("║       Self-contained game thread optimizer with intelligent       ║");
            Console.WriteLine("║                           detection                               ║");
            Console.WriteLine("╚═══════════════════════════════════════════════════════════════════╝");
            Console.ResetColor();
            Console.WriteLine();
        }
        #endregion
    }
}
