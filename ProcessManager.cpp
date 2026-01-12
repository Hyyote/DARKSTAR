#include "ProcessManager.h"

#include <tlhelp32.h>
#include <shellapi.h>
#include <powrprof.h>
#include <winsvc.h>

#include <algorithm>
#include <cwctype>
#include <functional>
#include <vector>
#include <unordered_set>

#ifdef _MSC_VER
#pragma comment(lib, "PowrProf.lib")
#endif

#include "Logger.h"

namespace
{
    template <typename T>
    size_t HashCombine(size_t seed, const T& value)
    {
        return seed ^ (std::hash<T>{}(value) + 0x9e3779b97f4a7c15ull + (seed << 6) + (seed >> 2));
    }

    std::wstring NormalizeName(const std::wstring& value)
    {
        std::wstring lower(value);
        std::transform(lower.begin(), lower.end(), lower.begin(), [](wchar_t c) { return std::towlower(c); });
        if (lower.size() > 4 && lower.substr(lower.size() - 4) == L".exe")
        {
            lower = lower.substr(0, lower.size() - 4);
        }
        return lower;
    }
}

ProcessManager::ProcessManager() = default;

void ProcessManager::ActivateGameMode(const GameInfo& game,
                                      const ConfigParser& config,
                                      ThreadManager& threadManager,
                                      CooldownTracker& cooldowns,
                                      const CpuTopology& topology,
                                      const OccupiedCorePolicy& policy,
                                      AutoAssignmentState& autoState)
{
    LOG_INFO("Activating game mode for %ls (PID %lu)", game.processName.c_str(), game.processId);

    gameModeActive_ = true;
    const SettingsSection& settings = config.GetSettings();

    // Always plan to relaunch explorer when game mode ends so users are not left without a shell.
    startExplorerOnExit_ = settings.enableKillExplorer;

    if (settings.enableKillExplorer)
    {
        explorerWasRunning_ = !EnumerateProcessIds(L"explorer").empty();
        KillExplorer();
    }

    if (settings.enableIdleSwitching)
    {
        idleStateDisabled_ = ApplyIdleState(true);
    }
    else
    {
        idleStateDisabled_ = false;
    }

    if (settings.lockCPUFrequency)
    {
        frequencyLocked_ = ApplyFrequencyLock(true);
    }
    else
    {
        frequencyLocked_ = false;
    }

    DisableMMCSS();

    Update(config, threadManager, cooldowns, topology, policy, autoState);
}

void ProcessManager::Update(const ConfigParser& config,
                            ThreadManager& threadManager,
                            CooldownTracker& cooldowns,
                            const CpuTopology& topology,
                            const OccupiedCorePolicy& policy,
                            AutoAssignmentState& autoState)
{
    const auto& ruleMap = config.GetProcessRules();
    const SettingsSection& settings = config.GetSettings();
    std::unordered_set<uint64_t> activeRuleKeys;
    
    // Determine if we should re-apply thread rules this update
    ULONGLONG now = ::GetTickCount64();
    bool shouldReapplyRules = false;
    
    if (lastThreadRuleApplication_ == 0)
    {
        // First run, always apply
        shouldReapplyRules = true;
        lastThreadRuleApplication_ = now;
    }
    else if ((now - lastThreadRuleApplication_) >= static_cast<ULONGLONG>(settings.threadRuleReapplyIntervalMs))
    {
        // Interval elapsed, check if processes changed
        if (HaveMonitoredProcessesChanged(config))
        {
            shouldReapplyRules = true;
            lastThreadRuleApplication_ = now;
        }
        else
        {
            // Interval elapsed but no process changes, still re-apply
            shouldReapplyRules = true;
            lastThreadRuleApplication_ = now;
        }
    }
    else
    {
        // Interval not elapsed, check if processes changed
        if (HaveMonitoredProcessesChanged(config))
        {
            shouldReapplyRules = true;
        }
    }

    if (shouldReapplyRules)
    {
        for (const auto& pair : ruleMap)
        {
            const std::wstring& processName = pair.first;
            const ProcessRuleSet& ruleSet = pair.second;

            autoState.Reset();
            std::vector<ThreadInfo> threads = threadManager.EnumerateProcessThreads(processName);
            if (threads.empty())
            {
                continue;
            }

            DWORD targetProcessId = threads.front().processId;

            if (ruleSet.hasPriorityClass)
            {
                threadManager.ApplyProcessPriorityClass(targetProcessId, ruleSet.priorityClass);
            }

            for (const ThreadRule& rule : ruleSet.rules)
            {
                auto matches = threadManager.FindMatchingThreads(threads, rule);
                if (matches.empty())
                {
                    continue;
                }

                size_t ruleHash = HashRule(processName, rule);

                if (rule.disableClones)
                {
                    ThreadRule firstRule = rule;
                    uint64_t key = MakeRuleKey(matches.front().threadId, ruleHash);
                    activeRuleKeys.insert(key);
                    
                    // Skip if applyOnce and already applied
                    if (rule.applyOnce && appliedOnceRules_.find(key) != appliedOnceRules_.end())
                    {
                        continue;
                    }
                    
                    ULONGLONG ruleNow = ::GetTickCount64();
                    if (ShouldApplyRule(key, ruleNow))
                    {
                        if (threadManager.ApplyThreadRule(matches.front(), firstRule, topology, policy, autoState, cooldowns))
                        {
                            ruleApplicationTimes_[key] = ::GetTickCount64();
                            if (rule.applyOnce)
                            {
                                appliedOnceRules_.insert(key);
                            }
                        }
                    }
                    continue;
                }

                for (const ThreadInfo& info : matches)
                {
                    uint64_t key = MakeRuleKey(info.threadId, ruleHash);
                    activeRuleKeys.insert(key);
                    
                    // Skip if applyOnce and already applied
                    if (rule.applyOnce && appliedOnceRules_.find(key) != appliedOnceRules_.end())
                    {
                        continue;
                    }
                    
                    ULONGLONG ruleNow = ::GetTickCount64();
                    if (!ShouldApplyRule(key, ruleNow))
                    {
                        continue;
                    }

                    if (threadManager.ApplyThreadRule(info, rule, topology, policy, autoState, cooldowns))
                    {
                        ruleApplicationTimes_[key] = ::GetTickCount64();
                        if (rule.applyOnce)
                        {
                            appliedOnceRules_.insert(key);
                        }
                    }
                }
            }
        }

        CleanupRuleCache(activeRuleKeys);
    }

    for (const auto& processName : config.GetDisableBoostList())
    {
        std::vector<ThreadInfo> threads = threadManager.EnumerateProcessThreads(processName);
        if (threads.empty())
        {
            continue;
        }

        threadManager.DisableProcessPriorityBoost(threads.front().processId, cooldowns);
    }

    if (gameModeActive_)
    {
        ApplySuspendPolicies(config);
        ApplyIdlePriorityPolicies(config);
        MaintainExplorerState(config.GetSettings());
    }
    else
    {
        if (!suspendedProcesses_.empty())
        {
            ResumeAllSuspendedProcesses();
        }
        if (!priorityRestore_.empty())
        {
            RestoreIdlePriorities();
        }
        if (explorerKilled_ && (explorerWasRunning_ || startExplorerOnExit_))
        {
            RestartExplorer();
            startExplorerOnExit_ = false;
        }
    }
}

bool ProcessManager::ShouldApplyRule(uint64_t key, ULONGLONG now)
{
    constexpr ULONGLONG kThreadRuleCooldownMs = 60000;
    auto it = ruleApplicationTimes_.find(key);
    if (it == ruleApplicationTimes_.end())
    {
        return true;
    }

    return (now - it->second) >= kThreadRuleCooldownMs;
}

void ProcessManager::CleanupRuleCache(const std::unordered_set<uint64_t>& activeKeys)
{
    if (activeKeys.empty())
    {
        ruleApplicationTimes_.clear();
        return;
    }

    for (auto it = ruleApplicationTimes_.begin(); it != ruleApplicationTimes_.end();)
    {
        if (activeKeys.find(it->first) == activeKeys.end())
        {
            it = ruleApplicationTimes_.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

size_t ProcessManager::HashRule(const std::wstring& processName, const ThreadRule& rule) const
{
    size_t hash = std::hash<std::wstring>{}(NormalizeName(processName));
    hash = HashCombine(hash, static_cast<size_t>(rule.matchType));
    hash = HashCombine(hash, std::hash<std::wstring>{}(rule.pattern));
    hash = HashCombine(hash, static_cast<size_t>(rule.wildcard));
    hash = HashCombine(hash, static_cast<size_t>(rule.isMainThread));
    hash = HashCombine(hash, static_cast<size_t>(rule.priority));
    hash = HashCombine(hash, static_cast<size_t>(rule.disableBoost));
    hash = HashCombine(hash, static_cast<size_t>(rule.suspendThread));
    hash = HashCombine(hash, static_cast<size_t>(rule.terminateThread));
    hash = HashCombine(hash, static_cast<size_t>(rule.disableClones));
    hash = HashCombine(hash, static_cast<size_t>(rule.applyOnce));
    hash = HashCombine(hash, static_cast<size_t>(rule.hasAffinityMask));
    hash = HashCombine(hash, static_cast<size_t>(rule.affinityMask));
    hash = HashCombine(hash, static_cast<size_t>(rule.useAutoAffinity));
    hash = HashCombine(hash, static_cast<size_t>(rule.autoAffinityPreference));
    hash = HashCombine(hash, static_cast<size_t>(rule.hasIdealProcessor));
    hash = HashCombine(hash, static_cast<size_t>(rule.idealProcessor));
    hash = HashCombine(hash, static_cast<size_t>(rule.useAutoIdealProcessor));
    hash = HashCombine(hash, static_cast<size_t>(rule.autoIdealPreference));
    hash = HashCombine(hash, static_cast<size_t>(rule.hasPriorityClassOverride));
    hash = HashCombine(hash, std::hash<std::wstring>{}(rule.priorityClassOverride));
    return hash;
}

uint64_t ProcessManager::MakeRuleKey(DWORD threadId, size_t ruleHash)
{
    return (static_cast<uint64_t>(threadId) << 32) ^ static_cast<uint64_t>(ruleHash);
}

void ProcessManager::DeactivateGameMode()
{
    if (!gameModeActive_ && !explorerKilled_ && suspendedProcesses_.empty() && priorityRestore_.empty() && !idleStateDisabled_ && !startExplorerOnExit_)
    {
        return;
    }

    gameModeActive_ = false;

    ResumeAllSuspendedProcesses();
    RestoreIdlePriorities();

    if (idleStateDisabled_)
    {
        RestoreIdleState();
        idleStateDisabled_ = false;
    }

    if (frequencyLocked_)
    {
        RestoreFrequencySettings();
        frequencyLocked_ = false;
    }

    appliedOnceRules_.clear();

    if (explorerKilled_ && (explorerWasRunning_ || startExplorerOnExit_))
    {
        RestartExplorer();
    }

    explorerKilled_ = false;
    explorerWasRunning_ = false;
    startExplorerOnExit_ = false;
}

std::vector<DWORD> ProcessManager::EnumerateProcessIds(const std::wstring& processName) const
{
    std::vector<DWORD> result;
    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return result;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (!Process32FirstW(snapshot, &entry))
    {
        ::CloseHandle(snapshot);
        return result;
    }

    const std::wstring normalizedTarget = NormalizeName(processName);

    do
    {
        if (NormalizeName(entry.szExeFile) == normalizedTarget)
        {
            result.push_back(entry.th32ProcessID);
        }
    } while (Process32NextW(snapshot, &entry));

    ::CloseHandle(snapshot);
    return result;
}

bool ProcessManager::SuspendProcess(DWORD processId, const std::wstring& processName)
{
    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);

    if (!Thread32First(snapshot, &entry))
    {
        ::CloseHandle(snapshot);
        return false;
    }

    SuspendedProcessState state;
    state.processId = processId;
    state.processName = processName;

    do
    {
        if (entry.th32OwnerProcessID != processId)
        {
            continue;
        }

        HANDLE thread = ::OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID);
        if (!thread)
        {
            continue;
        }

        DWORD previous = ::SuspendThread(thread);
        ::CloseHandle(thread);
        if (previous != static_cast<DWORD>(-1))
        {
            state.threadIds.push_back(entry.th32ThreadID);
        }
    } while (Thread32Next(snapshot, &entry));

    ::CloseHandle(snapshot);

    if (state.threadIds.empty())
    {
        return false;
    }

    suspendedProcesses_[processId] = std::move(state);
    LOG_INFO("Suspended process PID %lu", processId);
    return true;
}

void ProcessManager::ResumeProcess(DWORD processId)
{
    auto it = suspendedProcesses_.find(processId);
    if (it == suspendedProcesses_.end())
    {
        return;
    }

    for (DWORD threadId : it->second.threadIds)
    {
        HANDLE thread = ::OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
        if (!thread)
        {
            continue;
        }

        DWORD count = ::ResumeThread(thread);
        (void)count;
        ::CloseHandle(thread);
    }

    LOG_INFO("Resumed process PID %lu", processId);
    suspendedProcesses_.erase(it);
}

void ProcessManager::ResumeAllSuspendedProcesses()
{
    std::vector<DWORD> ids;
    ids.reserve(suspendedProcesses_.size());
    for (const auto& entry : suspendedProcesses_)
    {
        ids.push_back(entry.first);
    }

    for (DWORD pid : ids)
    {
        ResumeProcess(pid);
    }
}

void ProcessManager::ApplySuspendPolicies(const ConfigParser& config)
{
    const auto& suspendList = config.GetSuspendList();
    std::unordered_set<std::wstring> desired(suspendList.begin(), suspendList.end());

    for (const auto& name : suspendList)
    {
        auto pids = EnumerateProcessIds(name);
        for (DWORD pid : pids)
        {
            if (suspendedProcesses_.find(pid) != suspendedProcesses_.end())
            {
                continue;
            }

            SuspendProcess(pid, name);
        }
    }

    std::vector<DWORD> resumeList;
    for (const auto& entry : suspendedProcesses_)
    {
        if (desired.find(entry.second.processName) == desired.end() || !IsProcessRunning(entry.first))
        {
            resumeList.push_back(entry.first);
        }
    }

    for (DWORD pid : resumeList)
    {
        ResumeProcess(pid);
    }
}

void ProcessManager::ApplyIdlePriorityPolicies(const ConfigParser& config)
{
    const auto& idleList = config.GetIdleList();
    std::unordered_set<std::wstring> desired(idleList.begin(), idleList.end());

    for (const auto& name : idleList)
    {
        auto pids = EnumerateProcessIds(name);
        for (DWORD pid : pids)
        {
            if (priorityRestore_.find(pid) != priorityRestore_.end())
            {
                continue;
            }

            HANDLE process = ::OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (!process)
            {
                continue;
            }

            DWORD original = ::GetPriorityClass(process);
            if (original == 0)
            {
                ::CloseHandle(process);
                continue;
            }

            if (::SetPriorityClass(process, IDLE_PRIORITY_CLASS))
            {
                PriorityRestoreState state;
                state.processId = pid;
                state.processName = name;
                state.originalClass = original;
                priorityRestore_[pid] = state;
                LOG_INFO("Set %ls (PID %lu) to IDLE priority", name.c_str(), pid);
            }

            ::CloseHandle(process);
        }
    }

    std::vector<DWORD> restoreList;
    for (const auto& entry : priorityRestore_)
    {
        if (desired.find(entry.second.processName) == desired.end() || !IsProcessRunning(entry.first))
        {
            restoreList.push_back(entry.first);
        }
    }

    for (DWORD pid : restoreList)
    {
        RestorePriorityForProcess(pid);
    }
}

void ProcessManager::RestorePriorityForProcess(DWORD processId)
{
    auto it = priorityRestore_.find(processId);
    if (it == priorityRestore_.end())
    {
        return;
    }

    HANDLE process = ::OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (process)
    {
        ::SetPriorityClass(process, it->second.originalClass);
        ::CloseHandle(process);
        LOG_INFO("Restored priority for PID %lu", processId);
    }

    priorityRestore_.erase(it);
}

void ProcessManager::RestoreIdlePriorities()
{
    std::vector<DWORD> ids;
    ids.reserve(priorityRestore_.size());
    for (const auto& entry : priorityRestore_)
    {
        ids.push_back(entry.first);
    }

    for (DWORD pid : ids)
    {
        RestorePriorityForProcess(pid);
    }
}

bool ProcessManager::ApplyIdleState(bool disableIdle)
{
    GUID* activeScheme = nullptr;
    if (PowerGetActiveScheme(nullptr, &activeScheme) != ERROR_SUCCESS)
    {
        LOG_WARN("Failed to query active power scheme");
        return false;
    }

    DWORD value = disableIdle ? 1 : 0;
    GUID subgroup = GUID_PROCESSOR_SETTINGS_SUBGROUP;
    GUID setting = GUID_PROCESSOR_IDLE_DISABLE;

    bool success = true;
    if (PowerWriteACValueIndex(nullptr, activeScheme, &subgroup, &setting, value) != ERROR_SUCCESS)
    {
        success = false;
    }
    if (PowerWriteDCValueIndex(nullptr, activeScheme, &subgroup, &setting, value) != ERROR_SUCCESS)
    {
        success = false;
    }
    if (success && PowerSetActiveScheme(nullptr, activeScheme) != ERROR_SUCCESS)
    {
        success = false;
    }

    if (activeScheme)
    {
        ::LocalFree(activeScheme);
    }

    if (!success)
    {
        LOG_WARN("Failed to toggle processor idle state");
        return false;
    }

    LOG_INFO("Processor idle states %s", disableIdle ? "disabled" : "restored");
    return true;
}

void ProcessManager::RestoreIdleState()
{
    ApplyIdleState(false);
}

bool ProcessManager::ApplyFrequencyLock(bool lock)
{
    GUID* activeScheme = nullptr;
    if (PowerGetActiveScheme(nullptr, &activeScheme) != ERROR_SUCCESS)
    {
        LOG_WARN("Failed to query active power scheme for frequency lock");
        return false;
    }

    GUID subgroup = GUID_PROCESSOR_SETTINGS_SUBGROUP;
    
    // Processor boost mode GUID
    GUID boostGuid;
    boostGuid.Data1 = 0xbe337238;
    boostGuid.Data2 = 0x0d82;
    boostGuid.Data3 = 0x4146;
    boostGuid.Data4[0] = 0xa9;
    boostGuid.Data4[1] = 0x60;
    boostGuid.Data4[2] = 0x4f;
    boostGuid.Data4[3] = 0x37;
    boostGuid.Data4[4] = 0x49;
    boostGuid.Data4[5] = 0xd4;
    boostGuid.Data4[6] = 0x70;
    boostGuid.Data4[7] = 0xc7;

    // Min processor state GUID
    GUID minStateGuid;
    minStateGuid.Data1 = 0x893dee8e;
    minStateGuid.Data2 = 0x2bef;
    minStateGuid.Data3 = 0x41e0;
    minStateGuid.Data4[0] = 0x89;
    minStateGuid.Data4[1] = 0xc6;
    minStateGuid.Data4[2] = 0xb5;
    minStateGuid.Data4[3] = 0x5d;
    minStateGuid.Data4[4] = 0x09;
    minStateGuid.Data4[5] = 0x29;
    minStateGuid.Data4[6] = 0x96;
    minStateGuid.Data4[7] = 0x4c;

    // Max processor state GUID
    GUID maxStateGuid;
    maxStateGuid.Data1 = 0xbc5038f7;
    maxStateGuid.Data2 = 0x23e0;
    maxStateGuid.Data3 = 0x4960;
    maxStateGuid.Data4[0] = 0x96;
    maxStateGuid.Data4[1] = 0xda;
    maxStateGuid.Data4[2] = 0x33;
    maxStateGuid.Data4[3] = 0xab;
    maxStateGuid.Data4[4] = 0xaf;
    maxStateGuid.Data4[5] = 0x59;
    maxStateGuid.Data4[6] = 0x35;
    maxStateGuid.Data4[7] = 0xec;

    bool success = true;
    
    if (lock)
    {
        // Disable boost (0), set min/max to 100%
        if (PowerWriteACValueIndex(nullptr, activeScheme, &subgroup, &boostGuid, 0) != ERROR_SUCCESS)
            success = false;
        if (PowerWriteDCValueIndex(nullptr, activeScheme, &subgroup, &boostGuid, 0) != ERROR_SUCCESS)
            success = false;
        
        if (PowerWriteACValueIndex(nullptr, activeScheme, &subgroup, &minStateGuid, 100) != ERROR_SUCCESS)
            success = false;
        if (PowerWriteDCValueIndex(nullptr, activeScheme, &subgroup, &minStateGuid, 100) != ERROR_SUCCESS)
            success = false;
        
        if (PowerWriteACValueIndex(nullptr, activeScheme, &subgroup, &maxStateGuid, 100) != ERROR_SUCCESS)
            success = false;
        if (PowerWriteDCValueIndex(nullptr, activeScheme, &subgroup, &maxStateGuid, 100) != ERROR_SUCCESS)
            success = false;
    }
    else
    {
        // Restore: boost = 2, min = 5%, max = 100%
        if (PowerWriteACValueIndex(nullptr, activeScheme, &subgroup, &boostGuid, 2) != ERROR_SUCCESS)
            success = false;
        if (PowerWriteDCValueIndex(nullptr, activeScheme, &subgroup, &boostGuid, 2) != ERROR_SUCCESS)
            success = false;
        
        if (PowerWriteACValueIndex(nullptr, activeScheme, &subgroup, &minStateGuid, 5) != ERROR_SUCCESS)
            success = false;
        if (PowerWriteDCValueIndex(nullptr, activeScheme, &subgroup, &minStateGuid, 5) != ERROR_SUCCESS)
            success = false;
        
        if (PowerWriteACValueIndex(nullptr, activeScheme, &subgroup, &maxStateGuid, 100) != ERROR_SUCCESS)
            success = false;
        if (PowerWriteDCValueIndex(nullptr, activeScheme, &subgroup, &maxStateGuid, 100) != ERROR_SUCCESS)
            success = false;
    }

    if (success && PowerSetActiveScheme(nullptr, activeScheme) != ERROR_SUCCESS)
    {
        success = false;
    }

    if (activeScheme)
    {
        ::LocalFree(activeScheme);
    }

    if (!success)
    {
        LOG_WARN("Failed to apply CPU frequency lock settings");
        return false;
    }

    LOG_INFO("CPU frequency %s", lock ? "locked to base frequency" : "settings restored");
    return true;
}

void ProcessManager::RestoreFrequencySettings()
{
    ApplyFrequencyLock(false);
}

bool ProcessManager::HaveMonitoredProcessesChanged(const ConfigParser& config)
{
    std::unordered_set<DWORD> currentProcessIds;
    
    // Enumerate all monitored process names from the config
    const auto& ruleMap = config.GetProcessRules();
    for (const auto& pair : ruleMap)
    {
        const std::wstring& processName = pair.first;
        std::vector<DWORD> pids = EnumerateProcessIds(processName);
        for (DWORD pid : pids)
        {
            currentProcessIds.insert(pid);
        }
    }
    
    // Also check DisableBoost list
    for (const auto& processName : config.GetDisableBoostList())
    {
        std::vector<DWORD> pids = EnumerateProcessIds(processName);
        for (DWORD pid : pids)
        {
            currentProcessIds.insert(pid);
        }
    }
    
    // Compare with cached list
    bool changed = (currentProcessIds != lastKnownProcessIds_);
    
    // Update the cache
    lastKnownProcessIds_ = currentProcessIds;
    
    return changed;
}

bool ProcessManager::IsProcessRunning(DWORD processId) const
{
    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!process)
    {
        return false;
    }
    ::CloseHandle(process);
    return true;
}

void ProcessManager::MaintainExplorerState(const SettingsSection& settings)
{
    if (!settings.enableKillExplorer)
    {
        if (explorerKilled_ && explorerWasRunning_)
        {
            RestartExplorer();
            explorerWasRunning_ = false;
        }
        return;
    }

    auto explorers = EnumerateProcessIds(L"explorer");
    if (!explorers.empty())
    {
        KillExplorer();
        return;
    }

    const ULONGLONG now = ::GetTickCount64();
    const ULONGLONG interval = (std::max)(static_cast<ULONGLONG>(settings.explorerKillTimeoutMs), 1000ULL);
    if (now - lastExplorerKill_ >= interval)
    {
        lastExplorerKill_ = now;
    }
}

void ProcessManager::KillExplorer()
{
    auto explorers = EnumerateProcessIds(L"explorer");
    if (explorers.empty())
    {
        return;
    }

    explorerKilled_ = true;
    explorerWasRunning_ = true;
    lastExplorerKill_ = ::GetTickCount64();

    for (DWORD pid : explorers)
    {
        HANDLE process = ::OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!process)
        {
            continue;
        }

        if (::TerminateProcess(process, 0))
        {
            LOG_INFO("Terminated explorer.exe (PID %lu)", pid);
        }
        ::CloseHandle(process);
    }
}

void ProcessManager::RestartExplorer()
{
    explorerKilled_ = false;
    ::ShellExecuteW(nullptr, L"open", L"explorer.exe", nullptr, nullptr, SW_SHOWNORMAL);
    LOG_INFO("Explorer restored");
}

void ProcessManager::DisableMMCSS()
{
    SC_HANDLE scManager = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scManager)
    {
        LOG_WARN("Failed to open service manager for MMCSS");
        return;
    }

    SC_HANDLE service = ::OpenServiceW(scManager, L"MMCSS", SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!service)
    {
        ::CloseServiceHandle(scManager);
        return;
    }

    SERVICE_STATUS status{};
    if (::ControlService(service, SERVICE_CONTROL_STOP, &status))
    {
        LOG_INFO("MMCSS service stopped for TRUE GAME-MODE");
    }
    
    ::CloseServiceHandle(service);
    ::CloseServiceHandle(scManager);
}
