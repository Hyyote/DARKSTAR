using System;
using System.Runtime.InteropServices;

namespace DARKSTAR.Core
{
    public static class HotkeyManager
    {
        [DllImport("user32.dll")]
        private static extern short GetAsyncKeyState(int vKey);

        private const int VK_SHIFT = 0x10;
        private const int VK_CONTROL = 0x11;
        private const int VK_H = 0x48;
        private const int VK_G = 0x47;
        private const int VK_V = 0x56;

        private static DateTime _lastHotkeyCheck = DateTime.MinValue;
        private const int HOTKEY_CHECK_INTERVAL = 200;

        public static event Action? OnToggleConsoleRequested;
        public static event Action? OnToggleVerboseRequested;
        public static event Action? OnForceSystemOptimizationsRequested;

        public static void CheckHotkeys()
        {
            var now = DateTime.Now;

            if ((now - _lastHotkeyCheck).TotalMilliseconds < HOTKEY_CHECK_INTERVAL)
                return;

            bool ctrl = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
            bool shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
            bool h = (GetAsyncKeyState(VK_H) & 0x8000) != 0;
            bool g = (GetAsyncKeyState(VK_G) & 0x8000) != 0;
            bool v = (GetAsyncKeyState(VK_V) & 0x8000) != 0;

            if (ctrl && shift)
            {
                if (h || g || v)
                {
                    try { Logger.WriteVerbose($"Hotkey detected: CTRL+SHIFT+{(h ? "H" : g ? "G" : "V")}", ConsoleColor.Cyan); } catch { }
                }
            }

            if (ctrl && shift && h)
            {
                try { Logger.WriteLog("Hotkey: CTRL+SHIFT+H -> Toggle Console"); } catch { }
                Console.WriteLine("[HOTKEY] CTRL+SHIFT+H pressed -> Toggle Console");

                OnToggleConsoleRequested?.Invoke();
                _lastHotkeyCheck = now;
                return;
            }

            if (ctrl && shift && v)
            {
                try { Logger.WriteLog("Hotkey: CTRL+SHIFT+V -> Toggle Verbose"); } catch { }
                Console.WriteLine("[HOTKEY] CTRL+SHIFT+V pressed -> Toggle Verbose");

                OnToggleVerboseRequested?.Invoke();
                _lastHotkeyCheck = now;
                return;
            }

            if (ctrl && shift && g)
            {
                try { Logger.WriteLog("Hotkey: CTRL+SHIFT+G -> Force System Optimizations"); } catch { }
                Console.WriteLine("[HOTKEY] CTRL+SHIFT+G pressed -> Force System Optimizations");

                OnForceSystemOptimizationsRequested?.Invoke();
                _lastHotkeyCheck = now;
                return;
            }

            _lastHotkeyCheck = now;
        }
    }
}
