#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

enum class AutoCorePreference
{
    Any,
    PCore,
    ECore
};

enum class MatchType
{
    Module,
    ThreadDescription
};

struct ThreadRule
{
    MatchType matchType = MatchType::Module;
    std::wstring pattern;
    bool wildcard = false;
    bool isMainThread = false;

    int priority = 1000; // sentinel indicating not set
    bool disableBoost = false;
    bool suspendThread = false;
    bool terminateThread = false;
    bool disableClones = false;
    bool applyOnce = false;

    bool hasAffinityMask = false;
    unsigned long long affinityMask = 0ULL;

    bool useAutoAffinity = false;
    AutoCorePreference autoAffinityPreference = AutoCorePreference::Any;

    bool hasIdealProcessor = false;
    int idealProcessor = -1;

    bool useAutoIdealProcessor = false;
    AutoCorePreference autoIdealPreference = AutoCorePreference::Any;

    bool hasPriorityClassOverride = false;
    std::wstring priorityClassOverride;
};

struct ProcessRuleSet
{
    bool hasPriorityClass = false;
    std::wstring priorityClass;
    std::vector<ThreadRule> rules;
};

struct SettingsSection
{
    int updateTimeoutMs = 1000;
    int explorerKillTimeoutMs = 60000;
    bool enableKillExplorer = false;
    bool enableIdleSwitching = true;
    bool winBlockKeys = false;
    bool blockNonGamingMonitor = false;
    bool lockCPUFrequency = false;
    int threadRuleReapplyIntervalMs = 30000;

    bool affinityAuto = false;
    bool idealAuto = false;
    bool weakAuto = false;
    std::vector<int> occupiedAffinityPhysical;
    std::vector<int> occupiedIdealPhysical;
    std::vector<int> occupiedWeakPhysical;
};

class ConfigParser
{
public:
    bool Load(const std::wstring& path);

    const SettingsSection& GetSettings() const { return settings_; }
    const std::vector<std::wstring>& GetGameList() const { return games_; }
    const std::vector<std::wstring>& GetSuspendList() const { return suspendProcesses_; }
    const std::vector<std::wstring>& GetIdleList() const { return idleProcesses_; }
    const std::vector<std::wstring>& GetDisableBoostList() const { return disableBoostProcesses_; }
    const std::unordered_map<std::wstring, ProcessRuleSet>& GetProcessRules() const { return processRules_; }

private:
    SettingsSection settings_;
    std::vector<std::wstring> games_;
    std::vector<std::wstring> suspendProcesses_;
    std::vector<std::wstring> idleProcesses_;
    std::vector<std::wstring> disableBoostProcesses_;
    std::unordered_map<std::wstring, ProcessRuleSet> processRules_;

    static std::wstring Trim(const std::wstring& value);
    static bool EqualsIgnoreCase(const std::wstring& lhs, const std::wstring& rhs);
    static std::wstring ToLower(const std::wstring& value);
    void ParseSetting(const std::wstring& key, const std::wstring& value);
    void ParseListEntry(std::vector<std::wstring>& container, const std::wstring& line);
    void ParseThreadEntry(const std::wstring& processName,
                          const std::wstring& key,
                          const std::wstring& value);
    static bool ParseBoolean(const std::wstring& value, bool defaultValue);
    static std::vector<int> ParseCoreList(const std::wstring& text);
    static AutoCorePreference ParseCorePreference(const std::wstring& token);
    static bool TryParseInteger(const std::wstring& text, int& result);
};
