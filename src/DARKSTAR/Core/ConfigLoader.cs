using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace DARKSTAR.Core
{
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

    public static class ConfigLoader
    {
        private static readonly string CONFIG_DIR = ResolveConfigDir();
        private const string GAME_CONFIG_FILE = "GAME_PRIORITY.GCFG";
        private const string SYSTEM_CONFIG_FILE = "PROC_PRIORITY.GCFG";
        private const string GLOBAL_CONFIG_FILE = "DARKSTAR.GCFG";

        private static string GameConfigPath => Path.Combine(CONFIG_DIR, GAME_CONFIG_FILE);
        private static string SystemConfigPath => Path.Combine(CONFIG_DIR, SYSTEM_CONFIG_FILE);
        private static string GlobalConfigPath => Path.Combine(CONFIG_DIR, GLOBAL_CONFIG_FILE);

        public static string ResolvedConfigDir => CONFIG_DIR;

        private static readonly Dictionary<string, ProcessConfig> _gameConfigs = new Dictionary<string, ProcessConfig>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, ProcessConfig> _systemConfigs = new Dictionary<string, ProcessConfig>(StringComparer.OrdinalIgnoreCase);
        private static readonly HashSet<string> _disableBoostProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private static readonly Dictionary<string, int> _memoryLimitMb = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        private static bool _auto_apply_memory_caps_on_game_launch = false;

        private static bool _prompt_before_auto_memory_caps_on_game_launch = true;

        private static readonly HashSet<string> _auto_memory_caps_targets =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private static bool _networkThrottleEnabled = false;
        private static readonly HashSet<string> _networkThrottleProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static bool _autoIdleEnabled = false;
        private static bool _verboseStartup = false;

        public static Dictionary<string, ProcessConfig> GameConfigs => _gameConfigs;
        public static Dictionary<string, ProcessConfig> SystemConfigs => _systemConfigs;
        public static HashSet<string> DisableBoostProcesses => _disableBoostProcesses;

        public static Dictionary<string, int> MemoryLimitMb => _memoryLimitMb;

        public static bool AutoApplyMemoryCapsOnGameLaunch => _auto_apply_memory_caps_on_game_launch;

        public static bool PromptBeforeAutoMemoryCapsOnGameLaunch => _prompt_before_auto_memory_caps_on_game_launch;

        public static HashSet<string> AutoMemoryCapsTargets => _auto_memory_caps_targets;

        public static bool NetworkThrottleEnabled => _networkThrottleEnabled;
        public static HashSet<string> NetworkThrottleProcesses => _networkThrottleProcesses;
        public static bool AutoIdleEnabled => _autoIdleEnabled;
        public static bool VerboseStartup => _verboseStartup;

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
            catch
            {
            }

            LoadConfigFile(GameConfigPath, _gameConfigs, true);
            LoadConfigFile(SystemConfigPath, _systemConfigs, false);
            LoadGlobalConfiguration();
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
                    {
                        return candidateConfig;
                    }

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

        private static void LoadGlobalConfiguration()
        {
            if (!File.Exists(GlobalConfigPath))
            {
                Logger.WriteVerbose($"Global configuration file not found: {GlobalConfigPath} (using defaults)", ConsoleColor.Cyan);
                return;
            }

            Logger.WriteColored($"Loading Global configuration: {GlobalConfigPath}", ConsoleColor.Cyan);

            string[] lines = File.ReadAllLines(GlobalConfigPath);
            foreach (string line in lines)
            {
                string trimmed = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith("#") || trimmed.StartsWith("//"))
                    continue;

                if (trimmed.StartsWith("memory_limit_enabled", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (trimmed.StartsWith("auto_apply_memory_caps_on_game_launch", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = trimmed.Split('=');
                    if (parts.Length == 2 && bool.TryParse(parts[1].Trim(), out bool enabled))
                    {
                        _auto_apply_memory_caps_on_game_launch = enabled;
                    }
                    continue;
                }

                if (trimmed.StartsWith("prompt_before_auto_memory_caps_on_game_launch", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = trimmed.Split('=');
                    if (parts.Length == 2 && bool.TryParse(parts[1].Trim(), out bool enabled))
                    {
                        _prompt_before_auto_memory_caps_on_game_launch = enabled;
                    }
                    continue;
                }

                if (trimmed.StartsWith("auto_memory_caps_targets", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = trimmed.Split('=', 2);
                    if (parts.Length == 2)
                    {
                        _auto_memory_caps_targets.Clear();

                        var list = (parts[1] ?? "").Trim();
                        if (!string.IsNullOrWhiteSpace(list))
                        {
                            foreach (var name in list.Split(','))
                            {
                                var clean = (name ?? "").Trim();
                                if (string.IsNullOrWhiteSpace(clean))
                                    continue;

                                if (clean.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                                    clean = clean.Substring(0, clean.Length - 4);

                                if (!string.IsNullOrWhiteSpace(clean))
                                    _auto_memory_caps_targets.Add(clean);
                            }
                        }
                    }
                    continue;
                }

                if (trimmed.StartsWith("memory_cap_warning_disabled", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (trimmed.EndsWith("_memory_limit_mb", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = trimmed.Split('=');
                    if (parts.Length == 2 && int.TryParse(parts[1].Trim(), out int mb) && mb > 0)
                    {
                        string key = parts[0].Trim();
                        const string suffix = "_memory_limit_mb";
                        if (key.Length > suffix.Length)
                        {
                            string procName = key.Substring(0, key.Length - suffix.Length)
                                                 .Replace(".exe", string.Empty, StringComparison.OrdinalIgnoreCase);
                            _memoryLimitMb[procName] = mb;
                            Logger.WriteVerbose($"Memory limit: {procName} -> {mb} MB", ConsoleColor.DarkCyan);
                            Logger.WriteLog($"Memory limit: {procName} -> {mb} MB");
                        }
                    }
                    continue;
                }

                if (trimmed.StartsWith("network_throttle=", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = trimmed.Split('=');
                    if (parts.Length == 2 && bool.TryParse(parts[1].Trim(), out bool enabled))
                    {
                        _networkThrottleEnabled = enabled;
                        Logger.WriteVerbose($"Network throttling: {enabled}", ConsoleColor.Cyan);
                        Logger.WriteLog($"Network throttling: {enabled}");
                    }
                    continue;
                }

                if (trimmed.StartsWith("network_throttle_processes", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = trimmed.Split('=');
                    if (parts.Length == 2)
                    {
                        string list = parts[1].Trim();
                        foreach (var name in list.Split(','))
                        {
                            string clean = name.Trim();
                            if (!string.IsNullOrEmpty(clean))
                            {
                                _networkThrottleProcesses.Add(clean);
                            }
                        }
                        Logger.WriteVerbose($"Network throttle targets: {string.Join(", ", _networkThrottleProcesses)}", ConsoleColor.DarkCyan);
                        Logger.WriteLog($"Network throttle targets: {string.Join(", ", _networkThrottleProcesses)}");
                    }
                    continue;
                }

                if (trimmed.StartsWith("auto_idle=", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = trimmed.Split('=');
                    if (parts.Length == 2 && bool.TryParse(parts[1].Trim(), out bool enabled))
                    {
                        _autoIdleEnabled = enabled;
                        Logger.WriteVerbose($"Auto idle prevention: {enabled}", ConsoleColor.Cyan);
                        Logger.WriteLog($"Auto idle prevention: {enabled}");
                    }
                    continue;
                }

                if (trimmed.StartsWith("verbose_startup=", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = trimmed.Split('=');
                    if (parts.Length == 2 && bool.TryParse(parts[1].Trim(), out bool enabled))
                    {
                        _verboseStartup = enabled;
                        Logger.WriteVerbose($"Verbose startup: {enabled}", ConsoleColor.Cyan);
                        Logger.WriteLog($"Verbose startup: {enabled}");
                    }
                    continue;
                }
            }
        }

        private static void LoadConfigFile(string fileName, Dictionary<string, ProcessConfig> configs, bool isGame)
        {
            if (!File.Exists(fileName))
            {
                throw new FileNotFoundException($"Configuration file not found: {fileName}");
            }

            string[] lines = File.ReadAllLines(fileName);
            ProcessConfig? currentProcessConfig = null;
            string? currentProcess = null;
            bool inDisableBoostSection = false;

            string type = isGame ? "Game" : "System";
            Logger.WriteColored($"Loading {type} configuration: {fileName}", ConsoleColor.Cyan);

            foreach (string line in lines)
            {
                string trimmed = line.Trim();

                if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith("#") || trimmed.StartsWith("//"))
                    continue;

                if (trimmed.Equals("[DisableBoost]", StringComparison.OrdinalIgnoreCase))
                {
                    inDisableBoostSection = true;
                    currentProcessConfig = null;
                    currentProcess = null;
                    Logger.WriteVerbose($"Loading DisableBoost section from {fileName}", ConsoleColor.Cyan);
                    Logger.WriteLog($"Loading DisableBoost section from {fileName}");
                    continue;
                }

                if (trimmed.StartsWith("[") && trimmed.EndsWith("]"))
                {
                    inDisableBoostSection = false;
                    string processLine = trimmed.Substring(1, trimmed.Length - 2).Trim();
                    string[] processParts = processLine.Split(',');

                    if (processParts.Length >= 1)
                    {
                        currentProcess = processParts[0].Trim().Replace(".exe", string.Empty);
                        currentProcessConfig = new ProcessConfig();

                        if (processParts.Length >= 2 && int.TryParse(processParts[1].Trim(), out int procPriority))
                        {
                            currentProcessConfig.Priority = procPriority;
                        }

                        if (processParts.Length >= 3)
                        {
                            currentProcessConfig.Affinity = processParts[2].Trim().ToUpper();
                        }

                        if (processParts.Length >= 4 && bool.TryParse(processParts[3].Trim(), out bool procBoost))
                        {
                            currentProcessConfig.DisableBoost = procBoost;
                        }

                        if (processParts.Length >= 5)
                        {
                            currentProcessConfig.GpuPriority = Features.GpuPriorityManager.ParseGpuPriority(processParts[4].Trim());
                        }

                        configs[currentProcess] = currentProcessConfig;
                        Logger.WriteVerbose($"Loaded Process Config: {currentProcess} (Prio:{currentProcessConfig.Priority}, Aff:{currentProcessConfig.Affinity}, Boost:{!currentProcessConfig.DisableBoost}, GPU:{currentProcessConfig.GpuPriority})", ConsoleColor.Cyan);
                        Logger.WriteLog($"Loaded Process Config: {currentProcess}");
                    }
                    continue;
                }

                if (inDisableBoostSection)
                {
                    string processName = trimmed.Replace(".exe", "").Trim();
                    if (!string.IsNullOrEmpty(processName))
                    {
                        _disableBoostProcesses.Add(processName);
                        Logger.WriteVerbose($"  DisableBoost: {processName}", ConsoleColor.Cyan);
                        Logger.WriteLog($"  DisableBoost: {processName}");
                    }
                    continue;
                }

                if (currentProcess == null || currentProcessConfig == null)
                    continue;

                if (trimmed.StartsWith("module=", StringComparison.OrdinalIgnoreCase))
                {
                    string moduleLine = trimmed.Substring(7).Trim();
                    string[] moduleParts = moduleLine.Split(',');

                    if (moduleParts.Length >= 2)
                    {
                        string moduleName = moduleParts[0].Trim();
                        if (int.TryParse(moduleParts[1].Trim(), out int modulePriority))
                        {
                            currentProcessConfig.Modules[moduleName] = modulePriority;
                            Logger.WriteVerbose($"  Module Config: {moduleName} -> Priority {modulePriority}", ConsoleColor.DarkCyan);
                            Logger.WriteLog($"  Module Config: {moduleName} -> Priority {modulePriority}");
                        }
                    }
                    continue;
                }

                string[] parts = trimmed.Split('=');
                if (parts.Length == 2)
                {
                    string threadName = parts[0].Trim();
                    string configStr = parts[1].Trim();
                    string[] values = configStr.Split(',');

                    if (values.Length >= 1 && int.TryParse(values[0].Trim(), out int priority))
                    {
                        var config = new ThreadConfig { Priority = priority };

                        if (values.Length >= 2)
                        {
                            List<string> affinityParts = new List<string>();
                            for (int i = 1; i < values.Length; i++)
                            {
                                string val = values[i].Trim();
                                if (val.Equals("true", StringComparison.OrdinalIgnoreCase) ||
                                    val.Equals("false", StringComparison.OrdinalIgnoreCase))
                                {
                                    break;
                                }
                                affinityParts.Add(val);
                            }
                            config.Affinity = string.Join(",", affinityParts).ToUpper();
                        }

                        for (int i = 1; i < values.Length; i++)
                        {
                            string val = values[i].Trim();
                            if (bool.TryParse(val, out bool disableBoost))
                            {
                                config.DisableBoost = disableBoost;
                                break;
                            }
                        }

                        if (PriorityMap.ContainsKey(priority))
                        {
                            currentProcessConfig.Threads[threadName] = config;
                        }
                        else
                        {
                            Logger.WriteColored($"[WARNING] Invalid priority value {priority} for thread {threadName}", ConsoleColor.Cyan);
                            Logger.WriteLog($"[WARNING] Invalid priority value {priority} for thread {threadName}");
                        }
                    }
                }
            }

            Logger.WriteColored($"\n[OK] LOADED {configs.Count} PROCESS CONFIGURATIONS FROM {fileName}", ConsoleColor.Cyan);
            Logger.WriteColored($"[OK] LOADED {_disableBoostProcesses.Count} DISABLEBOOST PROCESSES FROM {fileName}", ConsoleColor.Cyan);
            Logger.WriteLog($"LOADED {configs.Count} PROCESS CONFIGURATIONS FROM {fileName}");
            Logger.WriteLog($"LOADED {_disableBoostProcesses.Count} DISABLEBOOST PROCESSES FROM {fileName}");
            Console.WriteLine();
        }
    }
}
