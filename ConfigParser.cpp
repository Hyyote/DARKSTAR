#include "ConfigParser.h"

#include <Windows.h>

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cwctype>

#include "Logger.h"

namespace
{
    constexpr int kUnsetPriority = 1000;

    std::string Narrow(const std::wstring& value)
    {
        if (value.empty())
        {
            return std::string();
        }

        int sizeRequired = ::WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (sizeRequired <= 1)
        {
            return std::string();
        }

        std::string buffer(static_cast<size_t>(sizeRequired - 1), '\0');
        ::WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, &buffer[0], sizeRequired, nullptr, nullptr);
        return buffer;
    }

    std::vector<std::wstring> Split(const std::wstring& text, wchar_t delimiter)
    {
        std::vector<std::wstring> parts;
        std::wstring current;
        for (wchar_t ch : text)
        {
            if (ch == delimiter)
            {
                if (!current.empty())
                {
                    parts.push_back(current);
                    current.clear();
                }
            }
            else
            {
                current.push_back(ch);
            }
        }
        if (!current.empty())
        {
            parts.push_back(current);
        }
        return parts;
    }
}

bool ConfigParser::Load(const std::wstring& path)
{
    settings_ = SettingsSection{};
    games_.clear();
    suspendProcesses_.clear();
    idleProcesses_.clear();
    disableBoostProcesses_.clear();
    processRules_.clear();

    std::ifstream file(Narrow(path));
    if (!file.is_open())
    {
        LOG_ERROR("Failed to open config file: %ls", path.c_str());
        return false;
    }

    std::wstring currentSection;
    std::string rawLine;
    while (std::getline(file, rawLine))
    {
        if (!rawLine.empty() && rawLine.back() == '\r')
        {
            rawLine.pop_back();
        }

        std::wstring line(rawLine.begin(), rawLine.end());
        line = Trim(line);
        if (line.empty())
        {
            continue;
        }

        if (line[0] == L'#' || line[0] == L';')
        {
            continue;
        }

        if (line.front() == L'[' && line.back() == L']')
        {
            currentSection = ToLower(line.substr(1, line.size() - 2));
            continue;
        }

        const size_t equalsPos = line.find(L'=');
        std::wstring key;
        std::wstring value;
        if (equalsPos != std::wstring::npos)
        {
            key = Trim(line.substr(0, equalsPos));
            value = Trim(line.substr(equalsPos + 1));
        }
        else
        {
            key = Trim(line);
            value = L"";
        }

        if (currentSection == L"settings")
        {
            ParseSetting(key, value);
        }
        else if (currentSection == L"games")
        {
            ParseListEntry(games_, key);
        }
        else if (currentSection == L"processestosuspend")
        {
            ParseListEntry(suspendProcesses_, key);
        }
        else if (currentSection == L"setprocessestoidlepriority")
        {
            ParseListEntry(idleProcesses_, key);
        }
        else if (currentSection == L"disableboost")
        {
            ParseListEntry(disableBoostProcesses_, key);
        }
        else if (!currentSection.empty())
        {
            ParseThreadEntry(currentSection, key, value);
        }
    }

    return true;
}

std::wstring ConfigParser::Trim(const std::wstring& value)
{
    size_t start = 0;
    size_t end = value.size();

    while (start < end && std::iswspace(value[start]))
    {
        ++start;
    }
    while (end > start && std::iswspace(value[end - 1]))
    {
        --end;
    }

    return value.substr(start, end - start);
}

bool ConfigParser::EqualsIgnoreCase(const std::wstring& lhs, const std::wstring& rhs)
{
    if (lhs.size() != rhs.size())
    {
        return false;
    }
    for (size_t i = 0; i < lhs.size(); ++i)
    {
        if (std::towlower(lhs[i]) != std::towlower(rhs[i]))
        {
            return false;
        }
    }
    return true;
}

std::wstring ConfigParser::ToLower(const std::wstring& value)
{
    std::wstring result(value);
    std::transform(result.begin(), result.end(), result.begin(), [](wchar_t c) { return std::towlower(c); });
    return result;
}

void ConfigParser::ParseSetting(const std::wstring& key, const std::wstring& value)
{
    if (EqualsIgnoreCase(key, L"updatetimeout"))
    {
        int parsed = settings_.updateTimeoutMs;
        if (TryParseInteger(value, parsed))
        {
            settings_.updateTimeoutMs = parsed;
        }
    }
    else if (EqualsIgnoreCase(key, L"explorerkilltimeout"))
    {
        int parsed = settings_.explorerKillTimeoutMs;
        if (TryParseInteger(value, parsed))
        {
            settings_.explorerKillTimeoutMs = parsed;
        }
    }
    else if (EqualsIgnoreCase(key, L"enablekillexplorer"))
    {
        settings_.enableKillExplorer = ParseBoolean(value, settings_.enableKillExplorer);
    }
    else if (EqualsIgnoreCase(key, L"enableidleswitching"))
    {
        settings_.enableIdleSwitching = ParseBoolean(value, settings_.enableIdleSwitching);
    }
    else if (EqualsIgnoreCase(key, L"winblockkeys"))
    {
        settings_.winBlockKeys = ParseBoolean(value, settings_.winBlockKeys);
    }
    else if (EqualsIgnoreCase(key, L"blocknogamingmonitor"))
    {
        settings_.blockNonGamingMonitor = ParseBoolean(value, settings_.blockNonGamingMonitor);
    }
    else if (EqualsIgnoreCase(key, L"enablescramble"))
    {
        settings_.enableScramble = ParseBoolean(value, settings_.enableScramble);
    }
    else if (EqualsIgnoreCase(key, L"scrambleintervalms"))
    {
        int parsed = settings_.scrambleIntervalMs;
        if (TryParseInteger(value, parsed))
        {
            settings_.scrambleIntervalMs = parsed;
        }
    }
    else if (EqualsIgnoreCase(key, L"occupied_affinity_cores"))
    {
        std::wstring lower = ToLower(value);
        settings_.affinityAuto = lower == L"auto";
        if (!settings_.affinityAuto)
        {
            settings_.occupiedAffinityPhysical = ParseCoreList(value);
        }
    }
    else if (EqualsIgnoreCase(key, L"occupied_ideal_processor_cores"))
    {
        std::wstring lower = ToLower(value);
        settings_.idealAuto = lower == L"auto";
        if (!settings_.idealAuto)
        {
            settings_.occupiedIdealPhysical = ParseCoreList(value);
        }
    }
    else if (EqualsIgnoreCase(key, L"occupied_weak_cores"))
    {
        std::wstring lower = ToLower(value);
        settings_.weakAuto = lower == L"auto";
        if (!settings_.weakAuto)
        {
            settings_.occupiedWeakPhysical = ParseCoreList(value);
        }
    }
    else if (EqualsIgnoreCase(key, L"threadrulereapplyinterval"))
    {
        int parsed = settings_.threadRuleReapplyIntervalMs;
        if (TryParseInteger(value, parsed))
        {
            settings_.threadRuleReapplyIntervalMs = parsed;
        }
    }
}

void ConfigParser::ParseListEntry(std::vector<std::wstring>& container, const std::wstring& line)
{
    std::wstring trimmed = Trim(line);
    if (trimmed.empty())
    {
        return;
    }

    container.push_back(ToLower(trimmed));
}

void ConfigParser::ParseThreadEntry(const std::wstring& processName,
                                    const std::wstring& key,
                                    const std::wstring& value)
{
    auto& ruleSet = processRules_[processName];

    if (EqualsIgnoreCase(key, L"priority_class"))
    {
        if (!value.empty())
        {
            ruleSet.hasPriorityClass = true;
            ruleSet.priorityClass = value;
        }
        else
        {
            ruleSet.hasPriorityClass = false;
            ruleSet.priorityClass.clear();
        }
        return;
    }

    ThreadRule rule;
    rule.priority = kUnsetPriority;

    std::wstring parameters = value;
    if (EqualsIgnoreCase(key, L"module"))
    {
        rule.matchType = MatchType::Module;
    }
    else if (EqualsIgnoreCase(key, L"threaddesc"))
    {
        rule.matchType = MatchType::ThreadDescription;
    }
    else
    {
        return;
    }

    size_t commaPos = parameters.find(L',');
    std::wstring pattern = commaPos == std::wstring::npos ? parameters : parameters.substr(0, commaPos);
    std::wstring modifiers = commaPos == std::wstring::npos ? L"" : parameters.substr(commaPos + 1);

    rule.pattern = Trim(pattern);

    if (rule.pattern.empty())
    {
        return;
    }

    if (!rule.pattern.empty() && rule.pattern.back() == L'*')
    {
        rule.isMainThread = true;
        rule.pattern.pop_back();
        rule.pattern = Trim(rule.pattern);
    }

    std::wstring workingPattern = rule.pattern;
    if (!workingPattern.empty() && workingPattern.front() == L'*')
    {
        rule.wildcard = true;
        workingPattern.erase(workingPattern.begin());
    }
    if (!workingPattern.empty() && workingPattern.back() == L'*')
    {
        rule.wildcard = true;
        workingPattern.pop_back();
    }
    rule.pattern = workingPattern;

    std::vector<std::wstring> tokens = Split(modifiers, L',');
    for (std::wstring& token : tokens)
    {
        token = Trim(token);
        if (token.empty())
        {
            continue;
        }

        if (token[0] == L'[' && token.back() == L']')
        {
            std::wstring inside = ToLower(Trim(token.substr(1, token.size() - 2)));
            if (inside == L"auto")
            {
                rule.useAutoAffinity = true;
                rule.autoAffinityPreference = AutoCorePreference::Any;
            }
            else
            {
                if (inside.size() > 2 && inside[0] == L'0' && (inside[1] == L'x' || inside[1] == L'X'))
                {
                    unsigned long long mask = 0ULL;
                    std::wstringstream ss;
                    ss << std::hex << inside.substr(2);
                    ss >> mask;
                    rule.hasAffinityMask = true;
                    rule.affinityMask = mask;
                }
            }
        }
        else if (token[0] == L'(' && token.back() == L')')
        {
            std::wstring inside = ToLower(Trim(token.substr(1, token.size() - 2)));
            if (inside == L"auto")
            {
                rule.useAutoIdealProcessor = true;
                rule.autoIdealPreference = AutoCorePreference::Any;
            }
            else
            {
                int logical = -1;
                if (TryParseInteger(inside, logical))
                {
                    rule.hasIdealProcessor = true;
                    rule.idealProcessor = logical;
                }
            }
        }
        else if (EqualsIgnoreCase(token, L"disableboost"))
        {
            rule.disableBoost = true;
        }
        else if (EqualsIgnoreCase(token, L"applyonce"))
        {
            rule.applyOnce = true;
        }
        else if (EqualsIgnoreCase(token, L"disableclones"))
        {
            rule.disableClones = true;
        }
        else if (EqualsIgnoreCase(token, L"pcore"))
        {
            if (rule.useAutoAffinity)
            {
                rule.autoAffinityPreference = AutoCorePreference::PCore;
            }
            if (rule.useAutoIdealProcessor)
            {
                rule.autoIdealPreference = AutoCorePreference::PCore;
            }
        }
        else if (EqualsIgnoreCase(token, L"ecore") || EqualsIgnoreCase(token, L"ecores"))
        {
            if (rule.useAutoAffinity)
            {
                rule.autoAffinityPreference = AutoCorePreference::ECore;
            }
            if (rule.useAutoIdealProcessor)
            {
                rule.autoIdealPreference = AutoCorePreference::ECore;
            }
        }
        else if (EqualsIgnoreCase(token, L"pcore_auto"))
        {
            rule.useAutoAffinity = true;
            rule.autoAffinityPreference = AutoCorePreference::PCore;
        }
        else if (EqualsIgnoreCase(token, L"ecore_auto"))
        {
            rule.useAutoAffinity = true;
            rule.autoAffinityPreference = AutoCorePreference::ECore;
        }
        else if (EqualsIgnoreCase(token, L"200"))
        {
            rule.terminateThread = true;
        }
        else if (EqualsIgnoreCase(token, L"300"))
        {
            rule.suspendThread = true;
        }
        else
        {
            int numeric = 0;
            if (TryParseInteger(token, numeric))
            {
                rule.priority = numeric;
            }
        }
    }

    ruleSet.rules.push_back(rule);
}

bool ConfigParser::ParseBoolean(const std::wstring& value, bool defaultValue)
{
    if (value.empty())
    {
        return defaultValue;
    }

    std::wstring lower = ToLower(value);
    if (lower == L"true" || lower == L"1" || lower == L"yes")
    {
        return true;
    }
    if (lower == L"false" || lower == L"0" || lower == L"no")
    {
        return false;
    }
    return defaultValue;
}

std::vector<int> ConfigParser::ParseCoreList(const std::wstring& text)
{
    std::vector<int> result;
    std::vector<std::wstring> tokens = Split(text, L',');
    for (const auto& token : tokens)
    {
        int value = 0;
        if (TryParseInteger(Trim(token), value))
        {
            result.push_back(value);
        }
    }
    return result;
}

AutoCorePreference ConfigParser::ParseCorePreference(const std::wstring& token)
{
    if (EqualsIgnoreCase(token, L"pcore"))
    {
        return AutoCorePreference::PCore;
    }
    if (EqualsIgnoreCase(token, L"ecore") || EqualsIgnoreCase(token, L"ecores"))
    {
        return AutoCorePreference::ECore;
    }
    return AutoCorePreference::Any;
}

bool ConfigParser::TryParseInteger(const std::wstring& text, int& result)
{
    if (text.empty())
    {
        return false;
    }

    wchar_t* endPtr = nullptr;
    long value = std::wcstol(text.c_str(), &endPtr, 10);
    if (endPtr == text.c_str())
    {
        return false;
    }
    result = static_cast<int>(value);
    return true;
}
