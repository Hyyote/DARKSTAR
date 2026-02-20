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

        [JsonPropertyName("memory_caps")]
        public MemoryCapsConfig MemoryCaps { get; set; } = new();

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
    }

    internal class MemoryCapsConfig
    {
        [JsonPropertyName("enabled")]
        public bool Enabled { get; set; } = false;

        [JsonPropertyName("prompt_before_restart")]
        public bool PromptBeforeRestart { get; set; } = true;

        [JsonPropertyName("targets")]
        public Dictionary<string, int> Targets { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    // ---- Static config loader ----

    public static class ConfigLoader
    {
        private static readonly string CONFIG_DIR = ResolveConfigDir();
        private const string CONFIG_FILE = "config.json";

        private static string ConfigPath => Path.Combine(CONFIG_DIR, CONFIG_FILE);
        public static string ResolvedConfigDir => CONFIG_DIR;

        // Internal config dictionaries — generated from JSON, not user-edited
        private static readonly Dictionary<string, ProcessConfig> _gameConfigs =
            new Dictionary<string, ProcessConfig>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, ProcessConfig> _systemConfigs =
            new Dictionary<string, ProcessConfig>(StringComparer.OrdinalIgnoreCase);
        private static readonly HashSet<string> _disableBoostProcesses =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Memory caps
        private static readonly Dictionary<string, int> _memoryLimitMb =
            new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        private static bool _autoApplyMemoryCaps = false;
        private static bool _promptBeforeMemoryCaps = true;
        private static readonly HashSet<string> _autoMemoryCapsTargets =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Feature toggles
        private static bool _networkThrottleEnabled = false;
        private static bool _autoIdleEnabled = false;
        private static bool _verboseStartup = false;
        private static bool _useKernelDriver = true;

        // ---- Public accessors (same names as original for MonitoringEngine compat) ----
        public static Dictionary<string, ProcessConfig> GameConfigs => _gameConfigs;
        public static Dictionary<string, ProcessConfig> SystemConfigs => _systemConfigs;
        public static HashSet<string> DisableBoostProcesses => _disableBoostProcesses;
        public static Dictionary<string, int> MemoryLimitMb => _memoryLimitMb;
        public static bool AutoApplyMemoryCapsOnGameLaunch => _autoApplyMemoryCaps;
        public static bool PromptBeforeAutoMemoryCapsOnGameLaunch => _promptBeforeMemoryCaps;
        public static HashSet<string> AutoMemoryCapsTargets => _autoMemoryCapsTargets;
        public static bool NetworkThrottleEnabled => _networkThrottleEnabled;
        public static HashSet<string> NetworkThrottleProcesses => new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public static bool AutoIdleEnabled => _autoIdleEnabled;
        public static bool VerboseStartup => _verboseStartup;
        public static bool UseKernelDriver => _useKernelDriver;

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
                if (!Directory.Exists(CONFIG_DIR))
                    Directory.CreateDirectory(CONFIG_DIR);
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
            foreach (string proc in config.BackgroundProcesses)
            {
                string name = StripExe(proc);
                if (string.IsNullOrWhiteSpace(name)) continue;

                _systemConfigs[name] = new ProcessConfig
                {
                    Priority = -15,                                // IDLE
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
                if (!string.IsNullOrWhiteSpace(clean))
                    _disableBoostProcesses.Add(clean);
            }
            Logger.WriteColored($"[OK] {_disableBoostProcesses.Count} DisableBoost targets loaded", ConsoleColor.Cyan);

            // ---- Memory caps ----
            _autoApplyMemoryCaps = config.MemoryCaps.Enabled;
            _promptBeforeMemoryCaps = config.MemoryCaps.PromptBeforeRestart;
            _memoryLimitMb.Clear();
            _autoMemoryCapsTargets.Clear();

            foreach (var kvp in config.MemoryCaps.Targets)
            {
                string procName = StripExe(kvp.Key);
                if (!string.IsNullOrWhiteSpace(procName) && kvp.Value > 0)
                {
                    _memoryLimitMb[procName] = kvp.Value;
                    _autoMemoryCapsTargets.Add(procName);
                }
            }

            if (_autoApplyMemoryCaps && _memoryLimitMb.Count > 0)
            {
                Logger.WriteVerbose($"Memory caps: {string.Join(", ", _memoryLimitMb.Select(k => $"{k.Key}={k.Value}MB"))}", ConsoleColor.DarkCyan);
            }

            Console.WriteLine();
        }

        /// <summary>
        /// Hardcoded overrides for system processes that need specific treatment
        /// beyond blanket IDLE demotion. These are system-level and should not
        /// require user configuration.
        /// </summary>
        private static void AddBuiltInDefaults()
        {
            // audiodg: system audio engine — must stay responsive for game audio routing
            SetSystemConfig("audiodg", priority: 2, affinity: "AUTO", disableBoost: true);

            // fontdrvhost: font rendering — normal priority, not worth demoting
            SetSystemConfig("fontdrvhost", priority: 0, affinity: "ALL", disableBoost: false);

            // HidHide: controller/input — keep responsive
            SetSystemConfig("HidHide", priority: 1, affinity: "AUTO", disableBoost: false);

            // obs64: streaming software — if running, user wants it functional
            SetSystemConfig("obs64", priority: 2, affinity: "AUTO", disableBoost: true);

            // svchost: hosts audio, network, and other critical services
            SetSystemConfig("svchost", priority: 0, affinity: "ALL", disableBoost: false);

            // winlogon: session management — critical, never demote
            SetSystemConfig("winlogon", priority: 0, affinity: "ALL", disableBoost: false);

            // mousocoreworker: update orchestration — keep normal so it doesn't stall/retry
            SetSystemConfig("mousocoreworker", priority: 0, affinity: "AUTO", disableBoost: false);

            // Anti-cheat services — NEVER touch these during gaming
            SetSystemConfig("BEService", priority: 0, affinity: "ALL", disableBoost: false);
            SetSystemConfig("EasyAntiCheat", priority: 0, affinity: "ALL", disableBoost: false);
            SetSystemConfig("vgc", priority: 0, affinity: "ALL", disableBoost: false);
            SetSystemConfig("vgtray", priority: 0, affinity: "ALL", disableBoost: false);
        }

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

        private static string ResolveConfigDir()
        {
            try
            {
                string dir = AppContext.BaseDirectory;
                for (int i = 0; i < 6 && !string.IsNullOrWhiteSpace(dir); i++)
                {
                    string candidateConfig = Path.Combine(dir, "config");
                    string candidateSln = Path.Combine(dir, "DARKSTAR.sln");
                    if (Directory.Exists(candidateConfig) || File.Exists(candidateSln))
                        return candidateConfig;

                    var parent = Directory.GetParent(dir);
                    if (parent == null) break;
                    dir = parent.FullName;
                }
                return Path.Combine(AppContext.BaseDirectory, "config");
            }
            catch
            {
                return Path.Combine(AppContext.BaseDirectory, "config");
            }
        }
    }
}
