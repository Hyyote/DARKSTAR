#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "ConfigParser.h"
#include "ThreadManager.h"
#include "GameDetector.h"

class ProcessManager
{
public:
    ProcessManager();

    void ActivateGameMode(const GameInfo& game,
                          const ConfigParser& config,
                          ThreadManager& threadManager,
                          CooldownTracker& cooldowns,
                          const CpuTopology& topology,
                          const OccupiedCorePolicy& policy,
                          AutoAssignmentState& autoState);

    void Update(const ConfigParser& config,
                ThreadManager& threadManager,
                CooldownTracker& cooldowns,
                const CpuTopology& topology,
                const OccupiedCorePolicy& policy,
                AutoAssignmentState& autoState);

    void DeactivateGameMode();

    void DisableMMCSS();

private:
    struct SuspendedProcessState
    {
        DWORD processId = 0;
        std::wstring processName;
        std::vector<DWORD> threadIds;
    };

    struct PriorityRestoreState
    {
        DWORD processId = 0;
        std::wstring processName;
        DWORD originalClass = NORMAL_PRIORITY_CLASS;
    };

    bool explorerKilled_ = false;
    bool explorerWasRunning_ = false;
    bool startExplorerOnExit_ = false;
    bool gameModeActive_ = false;
    bool idleStateDisabled_ = false;
    bool frequencyLocked_ = false;
    ULONGLONG lastExplorerKill_ = 0;
    ULONGLONG lastThreadRuleApplication_ = 0;

    std::unordered_map<DWORD, SuspendedProcessState> suspendedProcesses_;
    std::unordered_map<DWORD, PriorityRestoreState> priorityRestore_;
    std::unordered_map<uint64_t, ULONGLONG> ruleApplicationTimes_;
    std::unordered_set<DWORD> lastKnownProcessIds_;
    std::unordered_set<uint64_t> appliedOnceRules_;

    void KillExplorer();
    void RestartExplorer();
    void MaintainExplorerState(const SettingsSection& settings);
    std::vector<DWORD> EnumerateProcessIds(const std::wstring& processName) const;
    bool SuspendProcess(DWORD processId, const std::wstring& processName);
    void ResumeProcess(DWORD processId);
    void ResumeAllSuspendedProcesses();
    void ApplySuspendPolicies(const ConfigParser& config);
    void ApplyIdlePriorityPolicies(const ConfigParser& config);
    void RestoreIdlePriorities();
    void RestorePriorityForProcess(DWORD processId);
    bool ApplyIdleState(bool disableIdle);
    void RestoreIdleState();
    bool ApplyFrequencyLock(bool lock);
    void RestoreFrequencySettings();
    bool HaveMonitoredProcessesChanged(const ConfigParser& config);
    bool IsProcessRunning(DWORD processId) const;
    bool ShouldApplyRule(uint64_t key, ULONGLONG now);
    void CleanupRuleCache(const std::unordered_set<uint64_t>& activeKeys);
    size_t HashRule(const std::wstring& processName, const ThreadRule& rule) const;
    static uint64_t MakeRuleKey(DWORD threadId, size_t ruleHash);
};
