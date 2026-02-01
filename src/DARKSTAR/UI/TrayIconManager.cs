using System;
using System.Drawing;
using System.Windows.Forms;
using System.Runtime.InteropServices;

namespace DARKSTAR.UI
{
    public static class TrayIconManager
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool BringWindowToTop(IntPtr hWnd);

        private const int SW_HIDE = 0;
        private const int SW_SHOW = 5;

        private static NotifyIcon? _notifyIcon;

        public static void Initialize()
        {
            Application.EnableVisualStyles();
            Icon? appIcon = null;
            try
            {
                appIcon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            }
            catch
            {
                appIcon = SystemIcons.Shield;
            }
            _notifyIcon = new NotifyIcon
            {
                Icon = appIcon,
                Visible = true,
                Text = "DARKSTAR v1.0.0 - Running"
            };

            ContextMenuStrip menu = new ContextMenuStrip();
            ToolStripMenuItem showHideItem = new ToolStripMenuItem("Show/Hide Console");
            showHideItem.Click += (s, e) => ToggleConsole();
            menu.Items.Add(showHideItem);

            ToolStripMenuItem verboseItem = new ToolStripMenuItem("Toggle Verbose Logging");
            verboseItem.Click += (s, e) => ToggleVerboseLogging();
            menu.Items.Add(verboseItem);
            menu.Items.Add(new ToolStripSeparator());
            ToolStripMenuItem exitItem = new ToolStripMenuItem("Exit");
            exitItem.Click += (s, e) =>
            {
                Core.Logger.WriteLog("Application shutdown requested");
                _notifyIcon.Visible = false;
                Application.Exit();
                Environment.Exit(0);
            };
            menu.Items.Add(exitItem);
            _notifyIcon.ContextMenuStrip = menu;
            _notifyIcon.DoubleClick += (s, e) => ToggleConsole();
            _notifyIcon.ShowBalloonTip(3000, "DARKSTAR v1.0.0", "Monitoring started successfully", ToolTipIcon.Info);
        }

        public static void ShowBalloonTip(int timeoutMs, string title, string text, ToolTipIcon icon)
        {
            _notifyIcon?.ShowBalloonTip(timeoutMs, title, text, icon);
        }

        public static void SetText(string text)
        {
            if (_notifyIcon != null)
                _notifyIcon.Text = text;
        }

        private static void ToggleConsole()
        {
            IntPtr handle = GetConsoleWindow();
            if (handle != IntPtr.Zero)
            {
                if (IsWindowVisible(handle))
                {
                    ShowWindow(handle, SW_HIDE);
                    if (_notifyIcon != null)
                        _notifyIcon.Text = "DARKSTAR v1.0.0 - Hidden";
                    Core.Logger.WriteLog("Console hidden");
                }
                else
                {
                    ShowWindow(handle, SW_SHOW);
                    BringWindowToTop(handle);
                    if (_notifyIcon != null)
                        _notifyIcon.Text = "DARKSTAR v1.0.0 - Running";
                    Core.Logger.WriteLog("Console shown");
                }
            }
        }

        private static void ToggleVerboseLogging()
        {
            Core.Logger.ToggleVerbose();
            if (_notifyIcon != null)
            {
                if (Core.Logger.VerboseLogging)
                {
                    _notifyIcon.Text = "DARKSTAR v1.0.0 - Verbose";
                    _notifyIcon.ShowBalloonTip(2000, "DARKSTAR - Verbose Mode",
                        "Detailed logging enabled. Check console for verbose output.", ToolTipIcon.Info);
                }
                else
                {
                    _notifyIcon.Text = "DARKSTAR v1.0.0 - Running";
                    _notifyIcon.ShowBalloonTip(2000, "DARKSTAR - Normal Mode",
                        "Verbose logging disabled. Console output is now clean.", ToolTipIcon.Info);
                }
            }
        }

        public static void ShowConsole()
        {
            var consoleHandle = GetConsoleWindow();
            ShowWindow(consoleHandle, SW_SHOW);
        }
    }
}
