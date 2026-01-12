#pragma once

#include <Windows.h>

#include <string>
#include <vector>

struct GameInfo
{
    DWORD processId = 0;
    std::wstring processName;
    HWND windowHandle = nullptr;
};

class GameDetector
{
public:
    GameInfo DetectActiveGame(const std::vector<std::wstring>& games) const;

private:
    static std::wstring Normalize(const std::wstring& value);
    static std::wstring QueryProcessName(DWORD processId);
};
