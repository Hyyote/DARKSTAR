#pragma once

#include <string>
#include <mutex>
#include <fstream>
#include <cstdarg>

enum class LogLevel
{
    Error = 0,
    Warning,
    Info,
    Debug
};

class Logger
{
public:
    static Logger& Instance();
    static Logger& GetInstance() { return Instance(); }

    void SetLogFile(const std::wstring& path);
    void SetConsoleEnabled(bool enabled);
    void SetLevel(LogLevel level);

    void Log(LogLevel level, const char* format, ...);
    void LogV(LogLevel level, const char* format, std::va_list args);
    void LogF(LogLevel level, const char* format, ...);

    template <typename... Args>
    void Info(const char* format, Args... args)
    {
        Log(LogLevel::Info, format, args...);
    }

    template <typename... Args>
    void Warn(const char* format, Args... args)
    {
        Log(LogLevel::Warning, format, args...);
    }

    template <typename... Args>
    void Error(const char* format, Args... args)
    {
        Log(LogLevel::Error, format, args...);
    }

    template <typename... Args>
    void Debug(const char* format, Args... args)
    {
        Log(LogLevel::Debug, format, args...);
    }

private:
    Logger();

    std::wstring logPath_;
    std::ofstream stream_;
    std::mutex mutex_;
    bool consoleEnabled_;
    LogLevel minLevel_;

    void WriteLine(const std::string& line);
    static const char* ToString(LogLevel level);
};

#define LOG_ERROR(...) ((void)0)
#define LOG_WARN(...)  ((void)0)
#define LOG_WARNING(...) ((void)0)
#define LOG_INFO(...)  ((void)0)
#define LOG_DEBUG(...) ((void)0)
