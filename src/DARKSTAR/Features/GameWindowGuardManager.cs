using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using DARKSTAR.Core;

namespace DARKSTAR.Features
{
    public static class GameWindowGuardManager
    {
        private const int PollIntervalMs = 16;    // ~60Hz - one frame at 60fps for responsive clip
        private const int FullscreenTolerancePx = 4;
        private const double FullscreenCoverageThreshold = 0.95;
        private const int FocusGraceMs = 800;     // Grace period before releasing clip on focus loss

        private static Thread? _workerThread;
        private static volatile bool _running;
        private static bool _winKeyHookInstalled;
        private static bool _cursorClipActive;

        private static bool _winBlockKeysEnabled;
        private static bool _monitorBlockEnabled;
        private static bool _monitorAutoMode;
        private static readonly HashSet<int> _monitorWhitelist = new();

        private static IntPtr _keyboardHookHandle = IntPtr.Zero;
        private static HookProc? _keyboardHookProc;

        // Track the last known good clip rect so we can detect external overrides
        private static RECT _lastAppliedClip;
        // Track when the game was last seen as active foreground
        private static DateTime _lastGameActiveSeen = DateTime.MinValue;

        public static void Configure(bool winBlockKeysEnabled, string blockNoGamingMonitor)
        {
            _winBlockKeysEnabled = winBlockKeysEnabled;
            _monitorWhitelist.Clear();
            _monitorAutoMode = false;
            _monitorBlockEnabled = false;

            string mode = (blockNoGamingMonitor ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(mode) || mode.Equals("off", StringComparison.OrdinalIgnoreCase) || mode.Equals("false", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            _monitorBlockEnabled = true;
            if (mode.Equals("auto", StringComparison.OrdinalIgnoreCase))
            {
                _monitorAutoMode = true;
                return;
            }

            foreach (string token in mode.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (int.TryParse(token, out int monitorNumber) && monitorNumber > 0)
                    _monitorWhitelist.Add(monitorNumber);
            }

            if (_monitorWhitelist.Count == 0)
            {
                _monitorBlockEnabled = false;
            }
        }

        public static void Start()
        {
            if (_running || (!_winBlockKeysEnabled && !_monitorBlockEnabled))
                return;

            _running = true;
            _workerThread = new Thread(WorkerLoop)
            {
                IsBackground = true,
                Name = "GameWindowGuard"
            };
            _workerThread.SetApartmentState(ApartmentState.STA);
            _workerThread.Start();
        }

        private static void WorkerLoop()
        {
            Logger.WriteVerbose("[GUARD] GameWindowGuard manager started", ConsoleColor.DarkCyan);

            while (_running)
            {
                try
                {
                    // Pump pending messages so WH_KEYBOARD_LL hook callbacks fire.
                    // Low-level hooks require a message loop on the installing thread.
                    PumpMessages();

                    EvaluateGuardState();
                }
                catch (Exception ex)
                {
                    Logger.WriteLog($"[GUARD] ERROR: {ex.Message}");
                }

                Thread.Sleep(PollIntervalMs);
            }

            RemoveWinKeyHook();
            ReleaseCursorClip();
        }

        /// <summary>
        /// Process pending Windows messages on this thread.
        /// Required for WH_KEYBOARD_LL hook callbacks to be dispatched.
        /// </summary>
        private static void PumpMessages()
        {
            while (PeekMessage(out MSG msg, IntPtr.Zero, 0, 0, PM_REMOVE))
            {
                TranslateMessage(ref msg);
                DispatchMessage(ref msg);
            }
        }

        private static void EvaluateGuardState()
        {
            bool gameActive = IsConfiguredGameWindowActive(out IntPtr gameWindow);

            if (gameActive)
                _lastGameActiveSeen = DateTime.UtcNow;

            // Use grace period: don't immediately drop guard when focus is briefly lost
            // (steam overlays, notifications, game sub-windows)
            bool withinGrace = !gameActive &&
                               _lastGameActiveSeen != DateTime.MinValue &&
                               (DateTime.UtcNow - _lastGameActiveSeen).TotalMilliseconds < FocusGraceMs;

            bool shouldGuard = gameActive || withinGrace;

            if (_winBlockKeysEnabled)
            {
                if (shouldGuard)
                    EnsureWinKeyHook();
                else
                    RemoveWinKeyHook();
            }

            if (_monitorBlockEnabled)
            {
                if (gameActive)
                {
                    // Game is foreground - apply/reapply clip
                    TryApplyCursorClip(gameWindow);
                }
                else if (withinGrace && _cursorClipActive)
                {
                    // Within grace period - verify clip hasn't been overridden
                    VerifyAndReapplyClip();
                }
                else
                {
                    ReleaseCursorClip();
                }
            }
        }

        private static bool IsConfiguredGameWindowActive(out IntPtr gameWindow)
        {
            gameWindow = IntPtr.Zero;

            if (!Core.MonitoringEngine.GameOptimized)
                return false;

            IntPtr foregroundWindow = GetForegroundWindow();
            if (foregroundWindow == IntPtr.Zero)
                return false;

            if (!IsWindowVisible(foregroundWindow) || IsIconic(foregroundWindow))
                return false;

            _ = GetWindowThreadProcessId(foregroundWindow, out uint fgPid);
            if (fgPid == 0)
                return false;

            // Primary path: current monitored game process id
            if (Core.MonitoringEngine.GameProcessId > 0 && fgPid == (uint)Core.MonitoringEngine.GameProcessId)
            {
                gameWindow = foregroundWindow;
                return true;
            }

            // Fallback path: process name is in configured game list
            try
            {
                using var fgProcess = System.Diagnostics.Process.GetProcessById((int)fgPid);
                string processName = fgProcess.ProcessName;
                if (ConfigLoader.GameConfigs.ContainsKey(processName))
                {
                    gameWindow = foregroundWindow;
                    return true;
                }
            }
            catch
            {
            }

            return false;
        }

        private static void EnsureWinKeyHook()
        {
            if (_winKeyHookInstalled)
                return;

            _keyboardHookProc = KeyboardHookCallback;
            _keyboardHookHandle = SetWindowsHookEx(WH_KEYBOARD_LL, _keyboardHookProc, IntPtr.Zero, 0);
            _winKeyHookInstalled = _keyboardHookHandle != IntPtr.Zero;

            if (_winKeyHookInstalled)
                Logger.WriteLog("[GUARD] WINBLOCKKEYS active");
            else
                Logger.WriteLog($"[GUARD] Failed to install WIN key hook. Error={Marshal.GetLastWin32Error()}");
        }

        private static void RemoveWinKeyHook()
        {
            if (!_winKeyHookInstalled)
                return;

            UnhookWindowsHookEx(_keyboardHookHandle);
            _keyboardHookHandle = IntPtr.Zero;
            _winKeyHookInstalled = false;
            Logger.WriteLog("[GUARD] WINBLOCKKEYS inactive");
        }

        private static IntPtr KeyboardHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0)
            {
                int message = wParam.ToInt32();
                if (message == WM_KEYDOWN || message == WM_SYSKEYDOWN)
                {
                    var key = Marshal.PtrToStructure<KBDLLHOOKSTRUCT>(lParam);
                    if ((key.vkCode == VK_LWIN || key.vkCode == VK_RWIN) &&
                        Core.MonitoringEngine.GameOptimized &&
                        IsConfiguredGameWindowActive(out _))
                    {
                        return (IntPtr)1;
                    }
                }
            }

            return CallNextHookEx(_keyboardHookHandle, nCode, wParam, lParam);
        }

        private static void TryApplyCursorClip(IntPtr gameWindow)
        {
            if (gameWindow == IntPtr.Zero)
                return;

            IntPtr monitor = MonitorFromWindow(gameWindow, MONITOR_DEFAULTTONEAREST);
            if (monitor == IntPtr.Zero)
            {
                ReleaseCursorClip();
                return;
            }

            if (!_monitorAutoMode)
            {
                int monitorNumber = GetMonitorNumber(monitor);
                if (!_monitorWhitelist.Contains(monitorNumber))
                {
                    ReleaseCursorClip();
                    return;
                }
            }
            else
            {
                if (!IsWindowEffectivelyFullscreen(gameWindow, monitor))
                {
                    ReleaseCursorClip();
                    return;
                }
            }

            if (!TryGetMonitorRect(monitor, out RECT monitorRect))
            {
                ReleaseCursorClip();
                return;
            }

            // Always reapply the clip - other processes or the OS can override it at any time.
            // This is cheap (one syscall) and ensures the clip stays active.
            if (ClipCursor(ref monitorRect))
            {
                _lastAppliedClip = monitorRect;
                if (!_cursorClipActive)
                    Logger.WriteLog("[GUARD] BLOCKNOGAMINGMONITOR active");
                _cursorClipActive = true;
            }
        }

        /// <summary>
        /// Check if the current clip rect still matches what we applied.
        /// If something overrode it, reapply our clip.
        /// </summary>
        private static void VerifyAndReapplyClip()
        {
            if (!_cursorClipActive)
                return;

            if (GetClipCursor(out RECT currentClip))
            {
                if (currentClip.Left != _lastAppliedClip.Left ||
                    currentClip.Top != _lastAppliedClip.Top ||
                    currentClip.Right != _lastAppliedClip.Right ||
                    currentClip.Bottom != _lastAppliedClip.Bottom)
                {
                    // Clip was overridden - reapply
                    ClipCursor(ref _lastAppliedClip);
                }
            }
        }

        private static bool IsWindowEffectivelyFullscreen(IntPtr gameWindow, IntPtr monitor)
        {
            if (!TryGetMonitorRect(monitor, out RECT monitorRect) || !GetWindowRect(gameWindow, out RECT windowRect))
                return false;

            int monitorWidth = Math.Max(1, monitorRect.Right - monitorRect.Left);
            int monitorHeight = Math.Max(1, monitorRect.Bottom - monitorRect.Top);
            int windowWidth = Math.Max(0, windowRect.Right - windowRect.Left);
            int windowHeight = Math.Max(0, windowRect.Bottom - windowRect.Top);

            bool withinTolerance =
                Math.Abs(windowRect.Left - monitorRect.Left) <= FullscreenTolerancePx &&
                Math.Abs(windowRect.Top - monitorRect.Top) <= FullscreenTolerancePx &&
                Math.Abs(windowRect.Right - monitorRect.Right) <= FullscreenTolerancePx &&
                Math.Abs(windowRect.Bottom - monitorRect.Bottom) <= FullscreenTolerancePx;

            double monitorArea = (double)monitorWidth * monitorHeight;
            double windowArea = (double)windowWidth * windowHeight;
            bool coversEnough = (windowArea / monitorArea) >= FullscreenCoverageThreshold;

            return withinTolerance || coversEnough;
        }

        private static void ReleaseCursorClip()
        {
            if (!_cursorClipActive)
                return;

            ClipCursor(IntPtr.Zero);
            _cursorClipActive = false;
            _lastGameActiveSeen = DateTime.MinValue;
            Logger.WriteLog("[GUARD] BLOCKNOGAMINGMONITOR inactive");
        }

        private static bool TryGetMonitorRect(IntPtr monitor, out RECT monitorRect)
        {
            var info = new MONITORINFO { cbSize = Marshal.SizeOf<MONITORINFO>() };
            if (GetMonitorInfo(monitor, ref info))
            {
                monitorRect = info.rcMonitor;
                return true;
            }

            monitorRect = default;
            return false;
        }

        private static int GetMonitorNumber(IntPtr monitor)
        {
            int current = 0;
            int found = 1;

            MonitorEnumProc callback = (IntPtr hMonitor, IntPtr hdc, ref RECT lprcMonitor, IntPtr dwData) =>
            {
                current++;
                if (hMonitor == monitor)
                {
                    found = current;
                    return false;
                }
                return true;
            };

            EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, callback, IntPtr.Zero);
            return found;
        }

        #region Native
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_SYSKEYDOWN = 0x0104;
        private const int VK_LWIN = 0x5B;
        private const int VK_RWIN = 0x5C;
        private const uint MONITOR_DEFAULTTONEAREST = 2;
        private const uint PM_REMOVE = 0x0001;

        private delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);
        private delegate bool MonitorEnumProc(IntPtr hMonitor, IntPtr hdcMonitor, ref RECT lprcMonitor, IntPtr dwData);

        [StructLayout(LayoutKind.Sequential)]
        private struct KBDLLHOOKSTRUCT
        {
            public uint vkCode;
            public uint scanCode;
            public uint flags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MONITORINFO
        {
            public int cbSize;
            public RECT rcMonitor;
            public RECT rcWork;
            public uint dwFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MSG
        {
            public IntPtr hwnd;
            public uint message;
            public IntPtr wParam;
            public IntPtr lParam;
            public uint time;
            public int pt_x;
            public int pt_y;
        }

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool IsIconic(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, HookProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll")]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);

        [DllImport("user32.dll")]
        private static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFO lpmi);

        [DllImport("user32.dll")]
        private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("user32.dll")]
        private static extern bool ClipCursor(ref RECT lpRect);

        [DllImport("user32.dll")]
        private static extern bool ClipCursor(IntPtr lpRect);

        [DllImport("user32.dll")]
        private static extern bool GetClipCursor(out RECT lpRect);

        [DllImport("user32.dll")]
        private static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr lprcClip, MonitorEnumProc lpfnEnum, IntPtr dwData);

        [DllImport("user32.dll")]
        private static extern bool PeekMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax, uint wRemoveMsg);

        [DllImport("user32.dll")]
        private static extern bool TranslateMessage(ref MSG lpMsg);

        [DllImport("user32.dll")]
        private static extern IntPtr DispatchMessage(ref MSG lpMsg);

        #endregion
    }
}
