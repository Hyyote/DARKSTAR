#include <Windows.h>
#include <shellapi.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "ConfigParser.h"
#include "CPUTopology.h"
#include "GameDetector.h"
#include "HookManager.h"
#include "Logger.h"
#include "ProcessManager.h"
#include "ThreadManager.h"

namespace
{
    std::atomic<bool> g_running(true);

    BOOL WINAPI ConsoleCtrlHandler(DWORD ctrl)
    {
        switch (ctrl)
        {
        case CTRL_C_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            g_running = false;
            return TRUE;
        default:
            return FALSE;
        }
    }

    std::wstring GetExecutableDirectory()
    {
        wchar_t buffer[MAX_PATH] = {};
        DWORD length = ::GetModuleFileNameW(nullptr, buffer, MAX_PATH);
        if (length == 0 || length == MAX_PATH)
        {
            return L"";
        }

        std::wstring full(buffer, length);
        size_t pos = full.find_last_of(L"\\/");
        if (pos == std::wstring::npos)
        {
            return L"";
        }
        return full.substr(0, pos);
    }

    std::wstring CombinePath(const std::wstring& directory, const std::wstring& file)
    {
        if (directory.empty())
        {
            return file;
        }
        std::wstring path = directory;
        if (!path.empty() && path.back() != L'\\')
        {
            path.push_back(L'\\');
        }
        path += file;
        return path;
    }

    std::string DefaultConfig()
    {
        return R"(# DARKSTAR configuration inspired by TRUE GAME-MODE

[Settings]
UpdateTimeout=250
ExplorerKillTimeout=60000
EnableKillExplorer=false
EnableIdleSwitching=false
WinBlockKeys=false
BlockNoGamingMonitor=false
occupied_affinity_cores=auto
occupied_ideal_processor_cores=auto
occupied_weak_cores=

[Games]
# Add executables without extension (csgo, valorant, etc.)

[ProcessesToSuspend]
# List background processes (without .exe) to suspend while a game is active

[SetProcessesToIdlePriority]
# List background processes (without .exe) to set to IDLE priority

[DisableBoost]
dwm
audiodg
csrss

# Per-process thread rules. Section names are process names without .exe.
# Examples illustrate module-based and thread-description filters.
[dwm]
module=dwmcore.dll, [auto], ecore, disableboost
threaddesc=DWM Frame Update, [auto], pcore

[audiodg]
module=audiodg.exe, [auto], ecore, disableboost

[csgo]
module=csgo.exe*, [auto], pcore, disableboost
threaddesc=GameThread*, [auto], pcore
threaddesc=RenderThread, (auto), pcore
)";
    }

    bool EnsureConfigFile(const std::wstring& path)
    {
        DWORD attributes = ::GetFileAttributesW(path.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES)
        {
            return true;
        }

        HANDLE file = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        std::string content = DefaultConfig();
        DWORD written = 0;
        ::WriteFile(file, content.data(), static_cast<DWORD>(content.size()), &written, nullptr);
        ::CloseHandle(file);
        return written == content.size();
    }

    OccupiedCorePolicy BuildPolicy(const ConfigParser& config, const CpuTopology& topology)
    {
        OccupiedCorePolicy policy;
        const auto& settings = config.GetSettings();

        for (int core : settings.occupiedAffinityPhysical)
        {
            policy.forbiddenPhysical.insert(core);
        }
        for (int core : settings.occupiedIdealPhysical)
        {
            policy.forbiddenPhysical.insert(core);
        }
        for (int core : settings.occupiedWeakPhysical)
        {
            policy.weakPhysical.insert(core);
        }

        if (policy.weakPhysical.empty())
        {
            for (const auto& core : topology.GetCores())
            {
                if (core.type == CoreType::ECore)
                {
                    policy.weakPhysical.insert(core.physicalIndex);
                }
            }
        }

        if (topology.GetPhysicalCoreCount() > 0)
        {
            policy.forbiddenPhysical.insert(0);
        }

        return policy;
    }

    std::string DescribeCoreList(const std::unordered_set<int>& cores)
    {
        if (cores.empty())
        {
            return "none";
        }

        std::vector<int> ordered(cores.begin(), cores.end());
        std::sort(ordered.begin(), ordered.end());

        std::ostringstream oss;
        for (size_t i = 0; i < ordered.size(); ++i)
        {
            if (i > 0)
            {
                oss << ",";
            }
            oss << ordered[i];
        }
        return oss.str();
    }

    std::string SummarizePolicy(const SettingsSection& settings,
                                const OccupiedCorePolicy& policy,
                                const CpuTopology& topology)
    {
        const bool weakAuto = settings.weakAuto || (settings.occupiedWeakPhysical.empty() && !policy.weakPhysical.empty());
        const bool affinityAuto = settings.affinityAuto || settings.occupiedAffinityPhysical.empty();
        const bool idealAuto = settings.idealAuto || settings.occupiedIdealPhysical.empty();

        std::ostringstream oss;
        oss << "affinity=" << (affinityAuto ? "auto" : DescribeCoreList(policy.forbiddenPhysical));
        oss << " | ideal=" << (idealAuto ? "auto" : DescribeCoreList(policy.forbiddenPhysical));

        if (weakAuto)
        {
            oss << " | weak=auto";
            if (!policy.weakPhysical.empty())
            {
                oss << " (" << DescribeCoreList(policy.weakPhysical) << ")";
            }
        }
        else
        {
            oss << " | weak=" << DescribeCoreList(policy.weakPhysical);
        }

        oss << " | physical cores=" << topology.GetPhysicalCoreCount();
        return oss.str();
    }
}

int wmain()
{
    ::SetConsoleTitleW(L"DARKSTAR");
    ::SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    std::wstring baseDir = GetExecutableDirectory();
    std::wstring configPath = CombinePath(baseDir, L"darkstar.ini");
    std::wstring logPath = CombinePath(baseDir, L"DARKSTAR.log");

    Logger::Instance().SetLogFile(logPath);
    Logger::Instance().SetLevel(LogLevel::Info);

    if (!EnsureConfigFile(configPath))
    {
        LOG_ERROR("Failed to create configuration file at %ls", configPath.c_str());
        return 1;
    }

    HookManager hookManager;
    ConfigParser config;
    if (!config.Load(configPath))
    {
        LOG_ERROR("Failed to parse configuration file");
        return 1;
    }

    hookManager.Configure(config.GetSettings());

    CpuTopology topology;
    if (!topology.Refresh())
    {
        LOG_WARN("Failed to refresh CPU topology. Auto-affinity may be degraded.");
    }

    ThreadManager threadManager;
    ProcessManager processManager;
    GameDetector detector;
    CooldownTracker cooldowns;

    std::string lastPolicySummary;

    GameInfo activeGame;
    bool inGameMode = false;
    bool loggedNoActiveGame = false;
    bool loggedNoGamesConfigured = config.GetGameList().empty();

    if (loggedNoGamesConfigured)
    {
        LOG_WARN("No games configured in darkstar.ini. Add entries under [Games] to enable automation.");
    }
    else
    {
        LOG_INFO("Monitoring %zu configured titles for TRUE GAME-MODE rules.",
                 static_cast<unsigned long long>(config.GetGameList().size()));
    }

    LOG_INFO("DARKSTAR initialized.");

    while (g_running)
    {
        ConfigParser runtimeConfig;
        if (!runtimeConfig.Load(configPath))
        {
            LOG_WARN("Failed to reload configuration. Retaining previous settings.");
            runtimeConfig = config;
        }
        else
        {
            config = runtimeConfig;
        }

        hookManager.Configure(runtimeConfig.GetSettings());

        size_t gameCount = runtimeConfig.GetGameList().size();
        if (gameCount == 0)
        {
            if (!loggedNoGamesConfigured)
            {
                LOG_WARN("No games configured in darkstar.ini. Add entries under [Games] to enable automation.");
                loggedNoGamesConfigured = true;
            }
        }
        else if (loggedNoGamesConfigured)
        {
            LOG_INFO("Monitoring %zu configured titles for TRUE GAME-MODE rules.",
                     static_cast<unsigned long long>(gameCount));
            loggedNoGamesConfigured = false;
        }

        OccupiedCorePolicy policy = BuildPolicy(runtimeConfig, topology);
        std::string summary = SummarizePolicy(runtimeConfig.GetSettings(), policy, topology);
        if (summary != lastPolicySummary)
        {
            LOG_INFO("Core policy -> %s", summary.c_str());
            lastPolicySummary.swap(summary);
        }
        AutoAssignmentState autoState;
        autoState.Reset();

        GameInfo detected = detector.DetectActiveGame(runtimeConfig.GetGameList());
        if (detected.processId != 0)
        {
            if (!inGameMode || detected.processId != activeGame.processId)
            {
                activeGame = detected;
                processManager.ActivateGameMode(activeGame, runtimeConfig, threadManager, cooldowns,
                                                topology, policy, autoState);
                hookManager.Activate(activeGame);
                inGameMode = true;
                loggedNoActiveGame = false;
            }
        }
        else if (inGameMode)
        {
            hookManager.Deactivate();
            processManager.DeactivateGameMode();
            inGameMode = false;
            activeGame = GameInfo{};
            loggedNoActiveGame = false;
            LOG_INFO("No active game detected. TRUE GAME-MODE rules released.");
        }
        else if (gameCount > 0 && !loggedNoActiveGame)
        {
            LOG_INFO("Waiting for one of %zu configured titles to launch...",
                     static_cast<unsigned long long>(gameCount));
            loggedNoActiveGame = true;
        }

        processManager.Update(runtimeConfig, threadManager, cooldowns, topology, policy, autoState);

        if (inGameMode)
        {
            hookManager.Maintain(activeGame);
        }

        int timeout = runtimeConfig.GetSettings().updateTimeoutMs;
        if (timeout < 50)
        {
            timeout = 50;
        }

        for (int elapsed = 0; elapsed < timeout && g_running; elapsed += 50)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    hookManager.Deactivate();
    processManager.DeactivateGameMode();
    LOG_INFO("DARKSTAR shutting down.");
    return 0;
}
