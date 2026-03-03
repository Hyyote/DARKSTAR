using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DARKSTAR.Core
{
    // ========================================================================
    // REWRITE: Replaced 3 custom GCFG files + 450-line string parser with
    // a single config.json and System.Text.Json deserialization.
    //
    // WHAT CHANGED:
    //   - GAME_PRIORITY.GCFG (50+ games × per-thread/per-module configs) → GONE
    //     Games are now a flat list of exe names. IntelligentThreadDetector
    //     handles per-thread optimization automatically at runtime, which is
    //     what it was already designed to do. The GCFG per-thread configs were
    //     redundant with IntelligentThreadDetector and created massive parsing
    //     overhead at startup + bloated memory for configs that were rarely
    //     matched (most threads don't have stable names across game versions).
    //
    //   - PROC_PRIORITY.GCFG (60+ system procs × per-thread configs) → GONE
    //     Background processes are now a flat list. They all get demoted to
    //     IDLE during gaming. Processes that need special treatment (audiodg,
    //     svchost, anti-cheat) have hardcoded safe defaults in AddBuiltInDefaults().
    //
    //   - DARKSTAR.GCFG (global settings) → merged into config.json "settings"
    //
    // WHAT DIDN'T CHANGE:
    //   - ProcessConfig / ThreadConfig types are kept as internal data structures
    //     so MonitoringEngine's interface is unchanged.
    //   - All public property names (GameConfigs, SystemConfigs, UseKernelDriver,
    //     AutoIdleEnabled, etc.) are unchanged.
    //   - The game prompt in Main.cs still calls EnsureGameConfig() to add a
    //     runtime game entry — this works exactly as before.
    // ========================================================================

    public class ThreadConfig
    {
        public int Priority { get; set; }
        public string Affinity { get; set; } = "ALL";
        public bool DisableBoost { get; set; } = false;
    }

    public class ProcessConfig
    {
        public int Priority { get; set; }
        public string Affinity { get; set; } = "ALL";
        public bool DisableBoost { get; set; } = false;
        public Features.GpuPriority GpuPriority { get; set; } = Features.GpuPriority.None;
        public Dictionary<string, ThreadConfig> Threads { get; set; } = new Dictionary<string, ThreadConfig>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> Modules { get; set; } = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
    }

    // ---- JSON deserialization model ----

    internal class DarkstarConfig
    {
        [JsonPropertyName("games")]
        public List<string> Games { get; set; } = new();

        [JsonPropertyName("settings")]
        public DarkstarSettings Settings { get; set; } = new();

        [JsonPropertyName("background_processes")]
        public List<string> BackgroundProcesses { get; set; } = new();


        [JsonPropertyName("disable_boost")]
        public List<string> DisableBoost { get; set; } = new();
    }

    internal class DarkstarSettings
    {
        [JsonPropertyName("use_kernel_driver")]
        public bool UseKernelDriver { get; set; } = true;

        [JsonPropertyName("auto_idle")]
        public bool AutoIdle { get; set; } = false;

        [JsonPropertyName("verbose_startup")]
        public bool VerboseStartup { get; set; } = false;

        [JsonPropertyName("network_throttle")]
        public bool NetworkThrottle { get; set; } = false;

        [JsonPropertyName("win_block_keys")]
        public bool WinBlockKeys { get; set; } = false;

        [JsonPropertyName("WINBLOCKKEYS")]
        public bool WinBlockKeysLegacy { get; set; } = false;

        [JsonPropertyName("block_no_gaming_monitor")]
        public string BlockNoGamingMonitor { get; set; } = "";

        [JsonPropertyName("BLOCKNOGAMINGMONITOR")]
        public string BlockNoGamingMonitorLegacy { get; set; } = "";

        [JsonPropertyName("enable_dpc_core0_lock")]
        public bool EnableDpcCore0Lock { get; set; } = false;

        [JsonPropertyName("DPC_CORE0_LOCK")]
        public bool EnableDpcCore0LockLegacy { get; set; } = false;

        [JsonPropertyName("memory_drain")]
        public bool MemoryDrain { get; set; } = false;

        [JsonPropertyName("memory_drain_interval_ms")]
        public int MemoryDrainIntervalMs { get; set; } = 5000;

        [JsonPropertyName("memory_drain_timeout_ms")]
        public int MemoryDrainTimeoutMs { get; set; } = 4500;

        [JsonPropertyName("close_background_processes")]
        public bool CloseBackgroundProcesses { get; set; } = false;

        [JsonPropertyName("system_process_optimizer")]
        public bool SystemProcessOptimizer { get; set; } = true;
    }

    // ---- Static config loader ----

    public static class ConfigLoader
    {
        private static readonly string CONFIG_PATH = ResolveConfigPath();

        private static string ConfigPath => CONFIG_PATH;
        public static string ResolvedConfigDir => Path.GetDirectoryName(CONFIG_PATH) ?? AppContext.BaseDirectory;

        // Internal config dictionaries — generated from JSON, not user-edited
        private static readonly Dictionary<string, ProcessConfig> _gameConfigs =
            new Dictionary<string, ProcessConfig>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, ProcessConfig> _systemConfigs =
            new Dictionary<string, ProcessConfig>(StringComparer.OrdinalIgnoreCase);
        private static readonly HashSet<string> _disableBoostProcesses =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Raw background_processes from config.json — only these should be killed
        // by BackgroundProcessCloser. SystemConfigs also includes safe built-in
        // defaults (audiodg, svchost, winlogon, etc.) that must never be killed.
        private static readonly HashSet<string> _backgroundProcessNames =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // NOTE: _neverTouchProcesses is defined below AddBuiltInDefaults().
        // It contains game launchers, anti-cheat, system-critical, and shell
        // processes that must never enter _systemConfigs.

        // Feature toggles
        private static bool _networkThrottleEnabled = false;
        private static bool _autoIdleEnabled = false;
        private static bool _verboseStartup = false;
        private static bool _useKernelDriver = true;
        private static bool _winBlockKeysEnabled = false;
        private static string _blockNoGamingMonitorMode = "off";
        private static bool _dpcCore0LockEnabled = false;
        private static bool _memoryDrainEnabled = false;
        private static int _memoryDrainIntervalMs = 5000;
        private static int _memoryDrainTimeoutMs = 4500;
        private static bool _closeBackgroundProcesses = false;
        private static bool _systemProcessOptimizerEnabled = true;

        // ---- Public accessors (same names as original for MonitoringEngine compat) ----
        public static Dictionary<string, ProcessConfig> GameConfigs => _gameConfigs;
        public static Dictionary<string, ProcessConfig> SystemConfigs => _systemConfigs;
        public static HashSet<string> DisableBoostProcesses => _disableBoostProcesses;
        public static HashSet<string> BackgroundProcessNames => _backgroundProcessNames;
        public static bool NetworkThrottleEnabled => _networkThrottleEnabled;
        public static HashSet<string> NetworkThrottleProcesses => new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public static bool AutoIdleEnabled => _autoIdleEnabled;
        public static bool VerboseStartup => _verboseStartup;
        public static bool UseKernelDriver => _useKernelDriver;
        public static bool WinBlockKeysEnabled => _winBlockKeysEnabled;
        public static string BlockNoGamingMonitorMode => _blockNoGamingMonitorMode;
        public static bool DpcCore0LockEnabled => _dpcCore0LockEnabled;
        public static bool MemoryDrainEnabled => _memoryDrainEnabled;
        public static int MemoryDrainIntervalMs => _memoryDrainIntervalMs;
        public static int MemoryDrainTimeoutMs => _memoryDrainTimeoutMs;
        public static bool CloseBackgroundProcesses => _closeBackgroundProcesses;
        public static bool SystemProcessOptimizerEnabled => _systemProcessOptimizerEnabled;

        // Priority map (kept for logging)
        public static readonly Dictionary<int, string> PriorityMap = new Dictionary<int, string>
        {
            { 300, "SUSPEND" }, { 200, "TERMINATE" }, { 15, "TIME_CRITICAL" },
            { 2, "HIGHEST" }, { 1, "ABOVE_NORMAL" }, { 0, "NORMAL" },
            { -1, "BELOW_NORMAL" }, { -2, "LOWEST" }, { -15, "IDLE" }
        };

        public static void Load()
        {
            try
            {
                string? configDir = Path.GetDirectoryName(CONFIG_PATH);
                if (!string.IsNullOrWhiteSpace(configDir) && !Directory.Exists(configDir))
                    Directory.CreateDirectory(configDir);
            }
            catch { }

            if (!File.Exists(ConfigPath))
                throw new FileNotFoundException($"Configuration file not found: {ConfigPath}");

            Logger.WriteColored($"Loading configuration: {ConfigPath}", ConsoleColor.Cyan);

            DarkstarConfig config;
            try
            {
                string json = File.ReadAllText(ConfigPath);
                var options = new JsonSerializerOptions
                {
                    ReadCommentHandling = JsonCommentHandling.Skip,
                    AllowTrailingCommas = true
                };
                config = JsonSerializer.Deserialize<DarkstarConfig>(json, options)
                         ?? throw new InvalidOperationException("Failed to parse config.json");
            }
            catch (JsonException ex)
            {
                throw new InvalidOperationException($"Invalid JSON in config.json: {ex.Message}", ex);
            }

            // ---- Settings ----
            _useKernelDriver = config.Settings.UseKernelDriver;
            _autoIdleEnabled = config.Settings.AutoIdle;
            _verboseStartup = config.Settings.VerboseStartup;
            _networkThrottleEnabled = config.Settings.NetworkThrottle;
            _winBlockKeysEnabled = config.Settings.WinBlockKeys || config.Settings.WinBlockKeysLegacy;
            _blockNoGamingMonitorMode = !string.IsNullOrWhiteSpace(config.Settings.BlockNoGamingMonitor)
                ? config.Settings.BlockNoGamingMonitor.Trim()
                : config.Settings.BlockNoGamingMonitorLegacy.Trim();

            if (string.IsNullOrWhiteSpace(_blockNoGamingMonitorMode))
                _blockNoGamingMonitorMode = "off";

            _dpcCore0LockEnabled = config.Settings.EnableDpcCore0Lock || config.Settings.EnableDpcCore0LockLegacy;
            _memoryDrainEnabled = config.Settings.MemoryDrain;
            _memoryDrainIntervalMs = Math.Max(1000, config.Settings.MemoryDrainIntervalMs);
            _memoryDrainTimeoutMs = Math.Max(500, config.Settings.MemoryDrainTimeoutMs);
            _closeBackgroundProcesses = config.Settings.CloseBackgroundProcesses;
            _systemProcessOptimizerEnabled = config.Settings.SystemProcessOptimizer;

            // ---- Game configs ----
            // Every game gets the same process-level treatment. Thread-level
            // optimization is handled by IntelligentThreadDetector at runtime.
            _gameConfigs.Clear();
            foreach (string game in config.Games)
            {
                string name = StripExe(game);
                if (string.IsNullOrWhiteSpace(name)) continue;

                _gameConfigs[name] = new ProcessConfig
                {
                    Priority = 2,                                  // HIGHEST
                    Affinity = "ALL",
                    DisableBoost = true,
                    GpuPriority = Features.GpuPriority.High
                };
            }
            Logger.WriteColored($"[OK] {_gameConfigs.Count} game profiles loaded", ConsoleColor.Cyan);

            // ---- Background process configs ----
            _systemConfigs.Clear();
            _backgroundProcessNames.Clear();
            foreach (string proc in config.BackgroundProcesses)
            {
                string name = StripExe(proc);
                if (string.IsNullOrWhiteSpace(name)) continue;

                // Game launchers, anti-cheat, system-critical processes must never
                // enter _systemConfigs — MonitoringEngine would open handles to them.
                if (_neverTouchProcesses.Contains(name))
                {
                    Logger.WriteVerbose($"[CONFIG] Dropped protected process from background_processes: {name}", ConsoleColor.Yellow);
                    continue;
                }

                _backgroundProcessNames.Add(name);
                _systemConfigs[name] = new ProcessConfig
                {
                    Priority = -1,                                 // BELOW_NORMAL (was IDLE — too aggressive)
                    Affinity = "AUTO",
                    DisableBoost = true
                };
            }
            AddBuiltInDefaults();
            Logger.WriteColored($"[OK] {_systemConfigs.Count} background process profiles loaded", ConsoleColor.Cyan);

            // ---- DisableBoost ----
            _disableBoostProcesses.Clear();
            foreach (string name in config.DisableBoost)
            {
                string clean = StripExe(name);
                if (string.IsNullOrWhiteSpace(clean)) continue;
                // Don't track disable_boost for protected processes either — even
                // SetProcessPriorityBoost requires a handle to the process.
                if (_neverTouchProcesses.Contains(clean))
                {
                    Logger.WriteVerbose($"[CONFIG] Dropped protected process from disable_boost: {clean}", ConsoleColor.Yellow);
                    continue;
                }
                _disableBoostProcesses.Add(clean);
            }
            Logger.WriteColored($"[OK] {_disableBoostProcesses.Count} DisableBoost targets loaded", ConsoleColor.Cyan);
            Console.WriteLine();
        }

        /// <summary>
        /// Hardcoded overrides for system processes that need specific treatment
        /// beyond blanket IDLE demotion. These are system-level and should not
        /// require user configuration.
        /// </summary>
        private static void AddBuiltInDefaults()
        {
            // ONLY add entries where we actually change something (priority != 0
            // or affinity != ALL). No-op entries (priority 0, affinity ALL) cause
            // MonitoringEngine to open PROCESS_SET_INFORMATION handles for nothing,
            // which anti-cheat (VAC/EAC/BattlEye) flags as external manipulation.
            //
            // Processes we must NOT touch are in _neverTouchProcesses and get
            // silently dropped from background_processes in Load().

            // audiodg: system audio engine — must stay responsive for game audio routing
            SetSystemConfig("audiodg", priority: 2, affinity: "AUTO", disableBoost: true);

            // HidHide: controller/input — keep responsive
            SetSystemConfig("HidHide", priority: 1, affinity: "AUTO", disableBoost: false);

            // obs64: streaming software — if running, user wants it functional
            SetSystemConfig("obs64", priority: 2, affinity: "AUTO", disableBoost: true);
        }

        /// <summary>
        /// Processes that must NEVER enter _systemConfigs. Any process here gets
        /// silently dropped from background_processes and disable_boost during Load().
        ///
        /// WHY: MonitoringEngine.CheckForNewSystemProcesses() opens every process
        /// in _systemConfigs with PROCESS_SET_INFORMATION during gaming sessions.
        /// DARKSTAR runs with SeDebugPrivilege + a kernel driver loaded. Anti-cheat
        /// systems (VAC, EAC, BattlEye, Vanguard) detect this handle pattern and
        /// terminate the game + launcher. Even no-op entries (priority 0, affinity
        /// ALL) trigger detection because the handle itself is the red flag.
        ///
        /// Groups:
        ///  - Game launchers: IPC/overlay/anti-cheat dependencies
        ///  - Anti-cheat services: actively monitor for external OpenProcess calls
        ///  - System-critical/PPL: handled by SystemProcessOptimizer, not here
        ///  - Shell infrastructure: demoting breaks desktop/input
        /// </summary>
        private static readonly HashSet<string> _neverTouchProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // Game launchers
            "steam", "steamwebhelper", "steamservice", "SteamService",
            "EpicGamesLauncher", "EpicWebHelper",
            "RiotClientServices", "RiotClientUx", "RiotClientCrashHandler",
            "RobloxPlayerBeta", "RobloxCrashHandler",
            "UbisoftGameLauncher", "upc", "UplayWebCore",
            "GalaxyClient", "GalaxyClientHelper",
            "Origin", "OriginWebHelperService",
            "EADesktop", "EABackgroundService",
            "Battle.net", "BlizzardError",

            // Anti-cheat services — opening handles to these is instant detection
            "BEService", "BEService_x64",
            "EasyAntiCheat", "EasyAntiCheat_EOS",
            "vgc", "vgtray", "vgk",
            "atvi-pillar",

            // System-critical / PPL-protected — handled by SystemProcessOptimizer
            "csrss", "dwm", "lsass", "smss", "wininit", "winlogon", "services",

            // Shell infrastructure — demoting breaks desktop/input
            "conhost", "sihost", "ctfmon", "dllhost", "RuntimeBroker",
            "taskhostw", "ShellHost", "fontdrvhost",
            "svchost",   // hosts critical services (audio, network, etc.)
            "explorer",  // handled separately by BackgroundProcessCloser
        };

        private static void SetSystemConfig(string name, int priority, string affinity, bool disableBoost)
        {
            _systemConfigs[name] = new ProcessConfig
            {
                Priority = priority,
                Affinity = affinity,
                DisableBoost = disableBoost,
                GpuPriority = Features.GpuPriority.None
            };
        }

        private static string StripExe(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return "";
            string clean = name.Trim();
            if (clean.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                clean = clean[..^4];
            return clean.Trim();
        }

        private static string ResolveConfigPath()
        {
            try
            {
                string baseDir = AppContext.BaseDirectory;
                string primary = Path.Combine(baseDir, "config.json");
                if (File.Exists(primary))
                    return primary;

                string legacy = Path.Combine(baseDir, "config", "config.json");
                if (File.Exists(legacy))
                    return legacy;

                string dir = baseDir;
                for (int i = 0; i < 6 && !string.IsNullOrWhiteSpace(dir); i++)
                {
                    string candidate = Path.Combine(dir, "config.json");
                    if (File.Exists(candidate))
                        return candidate;

                    string candidateLegacy = Path.Combine(dir, "config", "config.json");
                    if (File.Exists(candidateLegacy))
                        return candidateLegacy;

                    string candidateSln = Path.Combine(dir, "DARKSTAR.sln");
                    if (File.Exists(candidateSln))
                        return candidate;

                    var parent = Directory.GetParent(dir);
                    if (parent == null) break;
                    dir = parent.FullName;
                }

                return primary;
            }
            catch
            {
                return Path.Combine(AppContext.BaseDirectory, "config.json");
            }
        }
    }
}
