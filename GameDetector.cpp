#include "GameDetector.h"

#include <Psapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cwctype>

namespace
{
    std::wstring ToLower(const std::wstring& value)
    {
        std::wstring lower(value);
        std::transform(lower.begin(), lower.end(), lower.begin(), [](wchar_t c) { return std::towlower(c); });
        return lower;
    }
}

GameInfo GameDetector::DetectActiveGame(const std::vector<std::wstring>& games) const
{
    GameInfo info;
    if (games.empty())
    {
        return info;
    }

    std::vector<std::wstring> normalized;
    normalized.reserve(games.size());
    for (const auto& game : games)
    {
        normalized.push_back(Normalize(game));
    }

    HWND foreground = ::GetForegroundWindow();
    if (foreground)
    {
        DWORD pid = 0;
        ::GetWindowThreadProcessId(foreground, &pid);
        std::wstring name = Normalize(QueryProcessName(pid));

        if (!name.empty())
        {
            for (const auto& candidate : normalized)
            {
                if (name == candidate)
                {
                    info.processId = pid;
                    info.windowHandle = foreground;
                    info.processName = name;
                    return info;
                }
            }
        }
    }

    // fallback: find first running instance in process list
    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return info;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry))
    {
        ::CloseHandle(snapshot);
        return info;
    }

    do
    {
        std::wstring name = Normalize(entry.szExeFile);
        for (const auto& candidate : normalized)
        {
            if (candidate == name)
            {
                info.processId = entry.th32ProcessID;
                info.processName = name;
                info.windowHandle = nullptr;
                ::CloseHandle(snapshot);
                return info;
            }
        }
    } while (Process32NextW(snapshot, &entry));

    ::CloseHandle(snapshot);
    return info;
}

std::wstring GameDetector::Normalize(const std::wstring& value)
{
    std::wstring lower = ToLower(value);
    if (lower.size() > 4 && lower.substr(lower.size() - 4) == L".exe")
    {
        lower = lower.substr(0, lower.size() - 4);
    }
    return lower;
}

std::wstring GameDetector::QueryProcessName(DWORD processId)
{
    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!process)
    {
        return L"";
    }

    wchar_t buffer[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    if (!::QueryFullProcessImageNameW(process, 0, buffer, &size))
    {
        ::CloseHandle(process);
        return L"";
    }

    ::CloseHandle(process);
    std::wstring path(buffer, size);
    size_t pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos)
    {
        return path.substr(pos + 1);
    }
    return path;
}
