#include "ThreadManager.h"

#include <Psapi.h>

#include <algorithm>
#include <cwctype>
#include <memory>
#include <type_traits>

#include "Logger.h"

namespace
{
    ULONGLONG GetTickCount64Safe()
    {
        return ::GetTickCount64();
    }

    int MapPriorityValue(int value)
    {
        if (value >= THREAD_PRIORITY_TIME_CRITICAL)
        {
            return THREAD_PRIORITY_TIME_CRITICAL;
        }
        if (value >= THREAD_PRIORITY_HIGHEST)
        {
            return THREAD_PRIORITY_HIGHEST;
        }
        if (value >= THREAD_PRIORITY_ABOVE_NORMAL)
        {
            return THREAD_PRIORITY_ABOVE_NORMAL;
        }
        if (value <= THREAD_PRIORITY_IDLE)
        {
            return THREAD_PRIORITY_IDLE;
        }
        if (value <= THREAD_PRIORITY_LOWEST)
        {
            return THREAD_PRIORITY_LOWEST;
        }
        if (value <= THREAD_PRIORITY_BELOW_NORMAL)
        {
            return THREAD_PRIORITY_BELOW_NORMAL;
        }
        return THREAD_PRIORITY_NORMAL;
    }

    std::wstring ToLower(const std::wstring& value)
    {
        std::wstring lower(value);
        std::transform(lower.begin(), lower.end(), lower.begin(), [](wchar_t c) { return std::towlower(c); });
        return lower;
    }
}

bool CooldownTracker::CanTrigger(std::unordered_map<DWORD, ULONGLONG>& map, DWORD key, ULONGLONG intervalMs)
{
    const ULONGLONG now = GetTickCount64Safe();
    auto it = map.find(key);
    if (it == map.end())
    {
        map[key] = now;
        return true;
    }

    if (now - it->second >= intervalMs)
    {
        it->second = now;
        return true;
    }
    return false;
}

ThreadManager::ThreadManager()
{
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (ntdll)
    {
        queryInformationThread_ = reinterpret_cast<NtQueryInformationThreadFunc>(
            ::GetProcAddress(ntdll, "NtQueryInformationThread"));
    }

    HMODULE kernel32 = ::GetModuleHandleW(L"kernel32.dll");
    if (kernel32)
    {
        getThreadDescription_ = reinterpret_cast<GetThreadDescriptionFunc>(
            ::GetProcAddress(kernel32, "GetThreadDescription"));
    }
}

std::vector<ThreadInfo> ThreadManager::EnumerateProcessThreads(const std::wstring& processName) const
{
    std::vector<ThreadInfo> threads;
    std::wstring normalized = NormalizeProcessName(processName);

    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return threads;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (!Process32FirstW(snapshot, &entry))
    {
        ::CloseHandle(snapshot);
        return threads;
    }

    do
    {
        std::wstring currentName = NormalizeProcessName(entry.szExeFile);
        if (currentName == normalized)
        {
            auto processThreads = EnumerateThreads(entry.th32ProcessID, currentName);
            threads.insert(threads.end(), processThreads.begin(), processThreads.end());
        }
    } while (Process32NextW(snapshot, &entry));

    ::CloseHandle(snapshot);
    return threads;
}

std::vector<ThreadInfo> ThreadManager::EnumerateThreads(DWORD processId, const std::wstring& processName) const
{
    std::vector<ThreadInfo> threads;

    moduleCache_.erase(processId);

    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return threads;
    }

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (!Thread32First(snapshot, &entry))
    {
        ::CloseHandle(snapshot);
        return threads;
    }

    do
    {
        if (entry.th32OwnerProcessID != processId)
        {
            continue;
        }

        HANDLE threadHandle = ::OpenThread(THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION |
                                           THREAD_SUSPEND_RESUME | THREAD_TERMINATE,
                                           FALSE,
                                           entry.th32ThreadID);
        if (!threadHandle)
        {
            continue;
        }

        ThreadInfo info;
        info.processId = processId;
        info.threadId = entry.th32ThreadID;
        info.processName = processName;
        info.startAddress = QueryThreadStartAddress(threadHandle);
        info.moduleName = ResolveModuleForAddress(processId, info.startAddress);
        info.threadDescription = QueryThreadDescription(threadHandle);
        info.priority = ::GetThreadPriority(threadHandle);

        threads.push_back(info);
        ::CloseHandle(threadHandle);
    } while (Thread32Next(snapshot, &entry));

    ::CloseHandle(snapshot);
    return threads;
}

std::vector<ThreadInfo> ThreadManager::FindMatchingThreads(const std::vector<ThreadInfo>& threads,
                                                           const ThreadRule& rule) const
{
    std::vector<ThreadInfo> matches;

    for (const ThreadInfo& info : threads)
    {
        std::wstring target;
        if (rule.matchType == MatchType::Module)
        {
            target = ToLower(info.moduleName);
        }
        else
        {
            target = ToLower(info.threadDescription);
        }

        if (target.empty())
        {
            continue;
        }

        std::wstring pattern = ToLower(rule.pattern);
        if (WildcardMatch(pattern, target, rule.wildcard))
        {
            matches.push_back(info);
        }
    }

    return matches;
}

bool ThreadManager::ApplyThreadRule(const ThreadInfo& thread,
                                    const ThreadRule& rule,
                                    const CpuTopology& topology,
                                    const OccupiedCorePolicy& policy,
                                    AutoAssignmentState& autoState,
                                    CooldownTracker& cooldowns) const
{
    HANDLE threadHandle = ::OpenThread(THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION |
                                       THREAD_SUSPEND_RESUME | THREAD_TERMINATE,
                                       FALSE,
                                       thread.threadId);
    if (!threadHandle)
    {
        LOG_WARN("Failed to open thread %lu", thread.threadId);
        return false;
    }

    auto closeHandle = std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&::CloseHandle)>(
        threadHandle, ::CloseHandle);

    bool success = false;

    // If the rule did not set a priority and this is a main thread, boost it aggressively.
    if (rule.priority == 1000 && rule.isMainThread)
    {
        if (::SetThreadPriority(threadHandle, THREAD_PRIORITY_HIGHEST))
        {
            success = true;
        }
    }
    else if (rule.priority != 1000)
    {
        int mapped = MapPriorityValue(rule.priority);
        if (::SetThreadPriority(threadHandle, mapped))
        {
            success = true;
            LOG_DEBUG("Set thread %lu priority to %d", thread.threadId, mapped);
        }
    }

    if (rule.disableBoost)
    {
        if (cooldowns.CanTrigger(cooldowns.threadBoost, thread.threadId, 300000))
        {
            if (::SetThreadPriorityBoost(threadHandle, TRUE))
            {
                success = true;
                LOG_DEBUG("Disabled priority boost for thread %lu", thread.threadId);
            }
        }
    }

    if (rule.terminateThread)
    {
        if (::TerminateThread(threadHandle, 1))
        {
            success = true;
            LOG_WARN("Terminated thread %lu", thread.threadId);
            return success;
        }
    }

    if (rule.suspendThread)
    {
        if (cooldowns.CanTrigger(cooldowns.threadSuspend, thread.threadId, 40000))
        {
            DWORD count = ::SuspendThread(threadHandle);
            if (count != static_cast<DWORD>(-1))
            {
                success = true;
                LOG_WARN("Suspended thread %lu", thread.threadId);
            }
        }
    }

    if (rule.hasAffinityMask)
    {
        if (ApplyAffinityMask(threadHandle, rule.affinityMask))
        {
            success = true;
        }
    }
    else if (rule.useAutoAffinity)
    {
        AutoSelection selection = SelectAutoCore(topology, policy, autoState,
                                                 rule.autoAffinityPreference,
                                                 rule.isMainThread);
        if (selection.valid)
        {
            if (ApplyAutoAffinity(threadHandle, selection))
            {
                success = true;
            }
            // Also set ideal processor to same core to reduce migrations
            if (ApplyAutoIdealProcessor(threadHandle, selection))
            {
                success = true;
            }
        }
    }

    if (rule.useAutoIdealProcessor)
    {
        AutoSelection selection = SelectAutoCore(topology, policy, autoState,
                                                 rule.autoIdealPreference,
                                                 rule.isMainThread);
        if (selection.valid)
        {
            if (ApplyAutoIdealProcessor(threadHandle, selection))
            {
                success = true;
            }
        }
    }
    else if (rule.hasIdealProcessor)
    {
        if (ApplyIdealProcessor(threadHandle, rule.idealProcessor))
        {
            success = true;
        }
    }

    return success;
}

bool ThreadManager::ApplyProcessPriorityClass(DWORD processId, const std::wstring& priorityClass) const
{
    HANDLE process = ::OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!process)
    {
        LOG_WARN("Failed to open process %lu for priority class", processId);
        return false;
    }

    auto closer = std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&::CloseHandle)>(process, ::CloseHandle);

    DWORD cls = NORMAL_PRIORITY_CLASS;
    std::wstring lower = ToLower(priorityClass);
    if (lower == L"idle")
    {
        cls = IDLE_PRIORITY_CLASS;
    }
    else if (lower == L"belownormal")
    {
        cls = BELOW_NORMAL_PRIORITY_CLASS;
    }
    else if (lower == L"abovenormal")
    {
        cls = ABOVE_NORMAL_PRIORITY_CLASS;
    }
    else if (lower == L"high")
    {
        cls = HIGH_PRIORITY_CLASS;
    }
    else if (lower == L"realtime")
    {
        cls = REALTIME_PRIORITY_CLASS;
    }

    if (!::SetPriorityClass(process, cls))
    {
        LOG_WARN("Failed to set priority class for process %lu", processId);
        return false;
    }

    LOG_INFO("Set process %lu priority class to %ls", processId, priorityClass.c_str());
    return true;
}

bool ThreadManager::DisableProcessPriorityBoost(DWORD processId, CooldownTracker& cooldowns) const
{
    if (!cooldowns.CanTrigger(cooldowns.processBoost, processId, 30000))
    {
        return false;
    }

    HANDLE process = ::OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!process)
    {
        return false;
    }

    auto closer = std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&::CloseHandle)>(process, ::CloseHandle);
    if (::SetProcessPriorityBoost(process, TRUE))
    {
        LOG_DEBUG("Disabled process priority boost for %lu", processId);
        return true;
    }
    return false;
}

bool ThreadManager::EnsureModuleSnapshot(DWORD processId) const
{
    if (moduleCache_.find(processId) != moduleCache_.end())
    {
        return true;
    }

    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    std::vector<ModuleRange> modules;
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry))
    {
        do
        {
            ModuleRange range;
            range.baseAddress = entry.modBaseAddr;
            range.size = entry.modBaseSize;
            range.name = ToLower(entry.szModule);
            modules.push_back(range);
        } while (Module32NextW(snapshot, &entry));
    }

    ::CloseHandle(snapshot);
    moduleCache_[processId] = std::move(modules);
    return true;
}

std::wstring ThreadManager::ResolveModuleForAddress(DWORD processId, PVOID address) const
{
    if (!address)
    {
        return L"";
    }

    EnsureModuleSnapshot(processId);
    auto it = moduleCache_.find(processId);
    if (it == moduleCache_.end())
    {
        return L"";
    }

    uintptr_t addr = reinterpret_cast<uintptr_t>(address);
    for (const ModuleRange& module : it->second)
    {
        uintptr_t base = reinterpret_cast<uintptr_t>(module.baseAddress);
        if (addr >= base && addr < base + module.size)
        {
            return module.name;
        }
    }

    return L"";
}

std::wstring ThreadManager::QueryThreadDescription(HANDLE thread) const
{
    if (!getThreadDescription_)
    {
        return L"";
    }

    PWSTR description = nullptr;
    if (SUCCEEDED(getThreadDescription_(thread, &description)) && description)
    {
        std::wstring result = description;
        ::LocalFree(description);
        return result;
    }

    return L"";
}

PVOID ThreadManager::QueryThreadStartAddress(HANDLE thread) const
{
    if (!queryInformationThread_)
    {
        return nullptr;
    }

    PVOID start = nullptr;
    NTSTATUS status = queryInformationThread_(thread, 9, &start, sizeof(start), nullptr);
    if (status >= 0)
    {
        return start;
    }
    return nullptr;
}

std::wstring ThreadManager::NormalizeProcessName(const std::wstring& name) const
{
    std::wstring lower = ToLower(name);
    if (lower.size() > 4 && lower.substr(lower.size() - 4) == L".exe")
    {
        lower = lower.substr(0, lower.size() - 4);
    }
    return lower;
}

bool ThreadManager::WildcardMatch(const std::wstring& pattern, const std::wstring& value, bool wildcard)
{
    if (pattern.empty())
    {
        return false;
    }

    if (wildcard)
    {
        return value.find(pattern) != std::wstring::npos;
    }

    return value == pattern;
}

bool ThreadManager::ApplyAffinityMask(HANDLE thread, unsigned long long mask) const
{
    DWORD_PTR previous = ::SetThreadAffinityMask(thread, static_cast<DWORD_PTR>(mask));
    if (previous == 0)
    {
        LOG_WARN("Failed to set affinity mask (error %lu)", GetLastError());
        return false;
    }
    return true;
}

bool ThreadManager::ApplyAutoAffinity(HANDLE thread, const AutoSelection& selection) const
{
    if (!selection.valid)
    {
        return false;
    }

    GROUP_AFFINITY affinity{};
    affinity.Group = static_cast<WORD>(selection.group);
    affinity.Mask = (static_cast<KAFFINITY>(1) << selection.groupNumber);

    if (!::SetThreadGroupAffinity(thread, &affinity, nullptr))
    {
        LOG_WARN("SetThreadGroupAffinity failed: %lu", GetLastError());
        return false;
    }

    return true;
}

bool ThreadManager::ApplyAutoIdealProcessor(HANDLE thread, const AutoSelection& selection) const
{
    if (!selection.valid)
    {
        return false;
    }

    PROCESSOR_NUMBER processor{};
    processor.Group = static_cast<WORD>(selection.group);
    processor.Number = static_cast<BYTE>(selection.groupNumber);
    processor.Reserved = 0;

    PROCESSOR_NUMBER previous{};
    if (!::SetThreadIdealProcessorEx(thread, &processor, &previous))
    {
        LOG_WARN("SetThreadIdealProcessorEx failed: %lu", GetLastError());
        return false;
    }
    return true;
}

bool ThreadManager::ApplyIdealProcessor(HANDLE thread, int logicalIndex) const
{
    if (logicalIndex < 0)
    {
        return false;
    }

    DWORD result = ::SetThreadIdealProcessor(thread, static_cast<DWORD>(logicalIndex));
    if (result == static_cast<DWORD>(-1))
    {
        LOG_WARN("SetThreadIdealProcessor failed: %lu", GetLastError());
        return false;
    }
    return true;
}
