#include "HookManager.h"

namespace
{
    bool AreRectsEqual(const RECT& lhs, const RECT& rhs)
    {
        return lhs.left == rhs.left && lhs.top == rhs.top &&
               lhs.right == rhs.right && lhs.bottom == rhs.bottom;
    }

    struct WindowSearchContext
    {
        DWORD processId = 0;
        HWND found = nullptr;
    };

    BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM param)
    {
        auto* context = reinterpret_cast<WindowSearchContext*>(param);
        if (!context)
        {
            return FALSE;
        }

        DWORD pid = 0;
        ::GetWindowThreadProcessId(hwnd, &pid);
        if (pid != context->processId)
        {
            return TRUE;
        }

        if (!::IsWindowVisible(hwnd))
        {
            return TRUE;
        }

        LONG style = ::GetWindowLongW(hwnd, GWL_STYLE);
        if ((style & WS_MINIMIZE) != 0)
        {
            return TRUE;
        }

        context->found = hwnd;
        return FALSE;
    }
}

HookManager* HookManager::instance_ = nullptr;

HookManager::HookManager()
{
    instance_ = this;
}

HookManager::~HookManager()
{
    Deactivate();
    if (instance_ == this)
    {
        instance_ = nullptr;
    }
}

void HookManager::Configure(const SettingsSection& settings)
{
    settings_ = settings;
    hasSettings_ = true;

    if (active_)
    {
        EvaluateKeyboardHook();
        EnsureCursorClip(activeGame_);
    }
}

void HookManager::Activate(const GameInfo& game)
{
    if (!hasSettings_)
    {
        return;
    }

    active_ = true;
    activeGame_ = game;

    EvaluateKeyboardHook();
    EnsureCursorClip(game);
}

void HookManager::Maintain(const GameInfo& game)
{
    if (!active_)
    {
        return;
    }

    activeGame_ = game;
    EvaluateKeyboardHook();
    EnsureCursorClip(game);
}

void HookManager::Deactivate()
{
    if (!active_)
    {
        return;
    }

    active_ = false;
    activeGame_ = GameInfo{};
    EvaluateKeyboardHook();
    ReleaseCursorClip();
}

void HookManager::EvaluateKeyboardHook()
{
    if (!hasSettings_ || !active_ || !settings_.winBlockKeys)
    {
        StopKeyboardThread();
        return;
    }

    EnsureKeyboardThread();
}

void HookManager::EnsureKeyboardThread()
{
    if (keyboardThread_)
    {
        if (::WaitForSingleObject(keyboardThread_, 0) == WAIT_OBJECT_0)
        {
            ::CloseHandle(keyboardThread_);
            keyboardThread_ = nullptr;
            keyboardThreadId_ = 0;
        }
        else
        {
            return;
        }
    }

    if (!keyboardReadyEvent_)
    {
        keyboardReadyEvent_ = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    }
    else
    {
        ::ResetEvent(keyboardReadyEvent_);
    }

    keyboardThread_ = ::CreateThread(nullptr, 0, KeyboardThreadProc, this, 0, &keyboardThreadId_);
    if (!keyboardThread_)
    {
        LOG_WARN("Failed to start keyboard hook thread (error %lu)", ::GetLastError());
        if (keyboardReadyEvent_)
        {
            ::CloseHandle(keyboardReadyEvent_);
            keyboardReadyEvent_ = nullptr;
        }
        return;
    }

    if (keyboardReadyEvent_)
    {
        DWORD waitResult = ::WaitForSingleObject(keyboardReadyEvent_, 2000);
        if (waitResult != WAIT_OBJECT_0 || !keyboardHook_)
        {
            LOG_WARN("Keyboard hook thread failed to initialize");
            StopKeyboardThread();
        }
    }
}

void HookManager::StopKeyboardThread()
{
    if (keyboardThread_)
    {
        if (keyboardThreadId_ != 0)
        {
            ::PostThreadMessageW(keyboardThreadId_, WM_QUIT, 0, 0);
        }

        ::WaitForSingleObject(keyboardThread_, 2000);
        ::CloseHandle(keyboardThread_);
        keyboardThread_ = nullptr;
        keyboardThreadId_ = 0;
    }

    if (keyboardReadyEvent_)
    {
        ::CloseHandle(keyboardReadyEvent_);
        keyboardReadyEvent_ = nullptr;
    }

    keyboardHook_ = nullptr;
}

DWORD WINAPI HookManager::KeyboardThreadProc(LPVOID param)
{
    HookManager* manager = static_cast<HookManager*>(param);
    MSG msg;
    ::PeekMessageW(&msg, nullptr, WM_USER, WM_USER, PM_NOREMOVE);

    HHOOK hook = ::SetWindowsHookExW(WH_KEYBOARD_LL, KeyboardProc, ::GetModuleHandleW(nullptr), 0);
    if (!hook)
    {
        LOG_WARN("Failed to install keyboard hook (error %lu)", ::GetLastError());
        if (manager->keyboardReadyEvent_)
        {
            ::SetEvent(manager->keyboardReadyEvent_);
        }
        return 0;
    }

    manager->keyboardHook_ = hook;
    if (manager->keyboardReadyEvent_)
    {
        ::SetEvent(manager->keyboardReadyEvent_);
    }

    LOG_INFO("Win-key block enabled while game is active");

    while (true)
    {
        BOOL result = ::GetMessageW(&msg, nullptr, 0, 0);
        if (result == 0 || result == -1)
        {
            break;
        }

        if (msg.message == WM_QUIT)
        {
            break;
        }
    }

    if (manager->keyboardHook_)
    {
        ::UnhookWindowsHookEx(manager->keyboardHook_);
        manager->keyboardHook_ = nullptr;
        LOG_INFO("Win-key block disabled");
    }

    return 0;
}

void HookManager::EnsureCursorClip(const GameInfo& game)
{
    if (!hasSettings_ || !active_ || !settings_.blockNonGamingMonitor)
    {
        ReleaseCursorClip();
        return;
    }

    HWND target = ResolveGameWindow(game);
    if (!target || !::IsWindow(target))
    {
        ReleaseCursorClip();
        return;
    }

    RECT windowRect;
    if (!::GetWindowRect(target, &windowRect))
    {
        ReleaseCursorClip();
        return;
    }

    // Adjust for window borders if present (get client area instead)
    LONG style = ::GetWindowLong(target, GWL_STYLE);
    if (style & WS_CAPTION)
    {
        RECT clientRect;
        if (!::GetClientRect(target, &clientRect))
        {
            ReleaseCursorClip();
            return;
        }
        
        POINT clientOrigin = {0, 0};
        if (!::ClientToScreen(target, &clientOrigin))
        {
            ReleaseCursorClip();
            return;
        }
        
        windowRect.left = clientOrigin.x;
        windowRect.top = clientOrigin.y;
        windowRect.right = windowRect.left + clientRect.right;
        windowRect.bottom = windowRect.top + clientRect.bottom;
    }

    if (cursorClipped_ && AreRectsEqual(windowRect, clipRect_))
    {
        return;
    }

    if (!::ClipCursor(&windowRect))
    {
        LOG_WARN("Failed to clip cursor (error %lu)", ::GetLastError());
        return;
    }

    clipRect_ = windowRect;
    cursorClipped_ = true;
    LOG_INFO("Cursor locked to active game window");
}

void HookManager::ReleaseCursorClip()
{
    if (!cursorClipped_)
    {
        return;
    }

    if (!::ClipCursor(nullptr))
    {
        LOG_WARN("Failed to release cursor clip (error %lu)", ::GetLastError());
    }
    cursorClipped_ = false;
    clipRect_ = RECT{};
    LOG_INFO("Cursor lock released");
}

HWND HookManager::ResolveGameWindow(const GameInfo& game) const
{
    if (game.windowHandle && ::IsWindow(game.windowHandle))
    {
        return game.windowHandle;
    }

    if (game.processId == 0)
    {
        return nullptr;
    }

    WindowSearchContext context;
    context.processId = game.processId;
    ::EnumWindows(EnumWindowsCallback, reinterpret_cast<LPARAM>(&context));
    return context.found;
}

LRESULT CALLBACK HookManager::KeyboardProc(int code, WPARAM wParam, LPARAM lParam)
{
    if (code < 0)
    {
        return ::CallNextHookEx(instance_ ? instance_->keyboardHook_ : nullptr, code, wParam, lParam);
    }

    if (!instance_ || !instance_->active_ || !instance_->hasSettings_)
    {
        return ::CallNextHookEx(instance_ ? instance_->keyboardHook_ : nullptr, code, wParam, lParam);
    }

    if (!instance_->settings_.winBlockKeys)
    {
        return ::CallNextHookEx(instance_->keyboardHook_, code, wParam, lParam);
    }

    const KBDLLHOOKSTRUCT* data = reinterpret_cast<const KBDLLHOOKSTRUCT*>(lParam);
    if (data && (data->vkCode == VK_LWIN || data->vkCode == VK_RWIN))
    {
        return 1;
    }

    return ::CallNextHookEx(instance_->keyboardHook_, code, wParam, lParam);
}
