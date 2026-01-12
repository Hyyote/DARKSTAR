#pragma once

#include <Windows.h>

#include "ConfigParser.h"
#include "GameDetector.h"
#include "Logger.h"

class HookManager
{
public:
    HookManager();
    ~HookManager();

    void Configure(const SettingsSection& settings);
    void Activate(const GameInfo& game);
    void Maintain(const GameInfo& game);
    void Deactivate();

private:
    static LRESULT CALLBACK KeyboardProc(int code, WPARAM wParam, LPARAM lParam);
    static HookManager* instance_;

    SettingsSection settings_{};
    bool hasSettings_ = false;
    bool active_ = false;
    bool cursorClipped_ = false;
    HHOOK keyboardHook_ = nullptr;
    HANDLE keyboardThread_ = nullptr;
    DWORD keyboardThreadId_ = 0;
    HANDLE keyboardReadyEvent_ = nullptr;
    RECT clipRect_{};
    GameInfo activeGame_{};

    void EvaluateKeyboardHook();
    void EnsureKeyboardThread();
    void StopKeyboardThread();
    static DWORD WINAPI KeyboardThreadProc(LPVOID param);
    void EnsureCursorClip(const GameInfo& game);
    void ReleaseCursorClip();
    HWND ResolveGameWindow(const GameInfo& game) const;
};
