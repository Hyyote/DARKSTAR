#include "Logger.h"

#include <Windows.h>
#include <vector>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <cstdio>

namespace
{
    std::string FormatString(const char* format, std::va_list args)
    {
        std::va_list copy;
        va_copy(copy, args);
        const int required = std::vsnprintf(nullptr, 0, format, copy);
        va_end(copy);

        if (required <= 0)
        {
            return {};
        }

        std::vector<char> buffer(static_cast<size_t>(required) + 1);
        std::vsnprintf(buffer.data(), buffer.size(), format, args);
        return std::string(buffer.data());
    }

    std::string CurrentTimestamp()
    {
        SYSTEMTIME local{};
        GetLocalTime(&local);

        std::ostringstream oss;
        oss << std::setfill('0')
            << std::setw(4) << local.wYear << '-'
            << std::setw(2) << local.wMonth << '-'
            << std::setw(2) << local.wDay << ' '
            << std::setw(2) << local.wHour << ':'
            << std::setw(2) << local.wMinute << ':'
            << std::setw(2) << local.wSecond << '.'
            << std::setw(3) << local.wMilliseconds;
        return oss.str();
    }
}

Logger& Logger::Instance()
{
    static Logger instance;
    return instance;
}

Logger::Logger()
    : consoleEnabled_(true),
      minLevel_(LogLevel::Info)
{
}

void Logger::SetLogFile(const std::wstring& path)
{
    std::lock_guard<std::mutex> lock(mutex_);
    logPath_ = path;
    stream_.close();
    stream_.open(path, std::ios::out | std::ios::app);
}

void Logger::SetConsoleEnabled(bool enabled)
{
    std::lock_guard<std::mutex> lock(mutex_);
    consoleEnabled_ = enabled;
}

void Logger::SetLevel(LogLevel level)
{
    std::lock_guard<std::mutex> lock(mutex_);
    minLevel_ = level;
}

void Logger::Log(LogLevel level, const char* format, ...)
{
    std::va_list args;
    va_start(args, format);
    LogV(level, format, args);
    va_end(args);
}

void Logger::LogV(LogLevel level, const char* format, std::va_list args)
{
    if (static_cast<int>(level) > static_cast<int>(minLevel_))
    {
        // Lower priority logs filtered out
        return;
    }

    const std::string message = FormatString(format, args);

    std::ostringstream oss;
    oss << '[' << CurrentTimestamp() << "] [" << ToString(level) << "] " << message;

    WriteLine(oss.str());
}

void Logger::LogF(LogLevel level, const char* format, ...)
{
    std::va_list args;
    va_start(args, format);
    LogV(level, format, args);
    va_end(args);
}

void Logger::WriteLine(const std::string& line)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (consoleEnabled_)
    {
        std::printf("%s\n", line.c_str());
    }

    if (stream_.is_open())
    {
        stream_ << line << '\n';
        stream_.flush();
    }
}

const char* Logger::ToString(LogLevel level)
{
    switch (level)
    {
    case LogLevel::Error:
        return "ERROR";
    case LogLevel::Warning:
        return "WARN";
    case LogLevel::Info:
        return "INFO";
    case LogLevel::Debug:
        return "DEBUG";
    default:
        return "LOG";
    }
}
