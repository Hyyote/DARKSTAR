#pragma once

#include <Windows.h>
#include <tlhelp32.h>

#include <vector>
#include <string>
#include <map>
#include <unordered_map>

#include "ConfigParser.h"
#include "CPUTopology.h"

struct ThreadInfo
{
    DWORD processId = 0;
    DWORD threadId = 0;
    std::wstring processName;
    std::wstring moduleName;
    std::wstring threadDescription;
    PVOID startAddress = nullptr;
    int priority = THREAD_PRIORITY_NORMAL;
    DWORD_PTR affinityMask = 0;
};

struct ModuleRange
{
    PVOID baseAddress = nullptr;
    SIZE_T size = 0;
    std::wstring name;
};

struct CooldownTracker
{
    std::unordered_map<DWORD, ULONGLONG> threadSuspend;
    std::unordered_map<DWORD, ULONGLONG> threadBoost;
    std::unordered_map<DWORD, ULONGLONG> processBoost;

    bool CanTrigger(std::unordered_map<DWORD, ULONGLONG>& map, DWORD key, ULONGLONG intervalMs);
};

class ThreadManager
{
public:
    ThreadManager();

    std::vector<ThreadInfo> EnumerateThreads(DWORD processId, const std::wstring& processName) const;
    std::vector<ThreadInfo> EnumerateProcessThreads(const std::wstring& processName) const;

    std::vector<ThreadInfo> FindMatchingThreads(const std::vector<ThreadInfo>& threads,
                                                const ThreadRule& rule) const;

    bool ApplyThreadRule(const ThreadInfo& thread,
                         const ThreadRule& rule,
                         const CpuTopology& topology,
                         const OccupiedCorePolicy& policy,
                         AutoAssignmentState& autoState,
                         CooldownTracker& cooldowns) const;

    bool ApplyProcessPriorityClass(DWORD processId, const std::wstring& priorityClass) const;
    bool DisableProcessPriorityBoost(DWORD processId, CooldownTracker& cooldowns) const;

private:
    using NtQueryInformationThreadFunc = NTSTATUS (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    NtQueryInformationThreadFunc queryInformationThread_ = nullptr;

    using GetThreadDescriptionFunc = HRESULT (WINAPI*)(HANDLE, PWSTR*);
    GetThreadDescriptionFunc getThreadDescription_ = nullptr;

    mutable std::unordered_map<DWORD, std::vector<ModuleRange>> moduleCache_;

    bool EnsureModuleSnapshot(DWORD processId) const;
    std::wstring ResolveModuleForAddress(DWORD processId, PVOID address) const;
    std::wstring QueryThreadDescription(HANDLE thread) const;
    PVOID QueryThreadStartAddress(HANDLE thread) const;
    std::wstring NormalizeProcessName(const std::wstring& name) const;
    static bool WildcardMatch(const std::wstring& pattern, const std::wstring& value, bool wildcard);
    bool ApplyAffinityMask(HANDLE thread, unsigned long long mask) const;
    bool ApplyAutoAffinity(HANDLE thread, const AutoSelection& selection) const;
    bool ApplyAutoIdealProcessor(HANDLE thread, const AutoSelection& selection) const;
    bool ApplyIdealProcessor(HANDLE thread, int logicalIndex) const;
};
