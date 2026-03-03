using System;
using System.Diagnostics;

namespace DARKSTAR.Features
{
    internal static class AutoIdleManager
    {
        private const string ProcessorSubGroupGuid = "sub_processor";
        private const string SettingGuid = "5d76a2ca-e8c0-402f-a133-2158492d58ad";

        private static bool _enabled;
        private static bool _active;

        public static void Configure(bool enabled)
        {
            _enabled = enabled;
            Console.WriteLine($"[AUTO-IDLE] configured: enabled={_enabled}");

            if (!_enabled && _active)
            {
                RestoreAfterGameSession();
            }
        }

        public static void EnableForGameSession()
        {
            if (!_enabled)
            {
                Console.WriteLine("[AUTO-IDLE] skipped enable: feature disabled");
                return;
            }

            if (_active)
            {
                Console.WriteLine("[AUTO-IDLE] skipped enable: already active");
                return;
            }

            Console.WriteLine("[AUTO-IDLE] GAME detected → disabling idle (powercfg)");
            Console.WriteLine($"[AUTO-IDLE] Running: powercfg /setacvalueindex scheme_current {ProcessorSubGroupGuid} {SettingGuid} 1");

            if (!RunPowerCfg($"/setacvalueindex scheme_current {ProcessorSubGroupGuid} {SettingGuid} 1"))
            {
                Console.WriteLine("[AUTO-IDLE] WARNING: powercfg setacvalueindex failed (disable).");
            }

            Console.WriteLine("[AUTO-IDLE] Running: powercfg /setactive scheme_current");
            if (!RunPowerCfg("/setactive scheme_current"))
            {
                Console.WriteLine("[AUTO-IDLE] WARNING: powercfg setactive failed (disable).");
            }

            _active = true;
            Console.WriteLine("[AUTO-IDLE] idle disabled for game session");
        }

        public static void RestoreAfterGameSession()
        {
            if (!_active)
            {
                Console.WriteLine("[AUTO-IDLE] skipped restore: not active");
                return;
            }

            Console.WriteLine("[AUTO-IDLE] GAME exited → restoring idle (powercfg)");
            Console.WriteLine($"[AUTO-IDLE] Running: powercfg /setacvalueindex scheme_current {ProcessorSubGroupGuid} {SettingGuid} 0");

            if (!RunPowerCfg($"/setacvalueindex scheme_current {ProcessorSubGroupGuid} {SettingGuid} 0"))
            {
                Console.WriteLine("[AUTO-IDLE] WARNING: powercfg setacvalueindex failed (restore).");
            }

            Console.WriteLine("[AUTO-IDLE] Running: powercfg /setactive scheme_current");
            if (!RunPowerCfg("/setactive scheme_current"))
            {
                Console.WriteLine("[AUTO-IDLE] WARNING: powercfg setactive failed (restore).");
            }

            _active = false;
            Console.WriteLine("[AUTO-IDLE] idle restored after game session");
        }

        private static bool RunPowerCfg(string args)
        {
            try
            {
                using var p = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "powercfg",
                        Arguments = args,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    }
                };

                p.Start();

                string _ = p.StandardOutput.ReadToEnd();
                string err = p.StandardError.ReadToEnd();

                p.WaitForExit();

                if (p.ExitCode != 0)
                {
                    if (!string.IsNullOrWhiteSpace(err))
                        Console.WriteLine($"[AUTO-IDLE] powercfg error: {err.Trim()}");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[AUTO-IDLE] powercfg launch failed: {ex.Message}");
                return false;
            }
        }
    }
}
