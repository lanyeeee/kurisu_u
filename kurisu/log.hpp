#pragma once
#include "detail/log_file.hpp"
#include "detail/logger.hpp"

namespace kurisu {
#define LOG_TRACE \
    if (kurisu::Logger::level() <= kurisu::Logger::LogLevel::TRACE) \
    kurisu::Logger(__FILE__, __LINE__, kurisu::Logger::LogLevel::TRACE, __func__).stream()
#define LOG_DEBUG \
    if (kurisu::Logger::level() <= kurisu::Logger::LogLevel::DEBUG) \
    kurisu::Logger(__FILE__, __LINE__, kurisu::Logger::LogLevel::DEBUG, __func__).stream()
#define LOG_INFO \
    if (kurisu::Logger::level() <= kurisu::Logger::LogLevel::INFO) \
    kurisu::Logger(__FILE__, __LINE__).stream()
#define LOG_WARN kurisu::Logger(__FILE__, __LINE__, kurisu::Logger::LogLevel::WARN).stream()
#define LOG_ERROR kurisu::Logger(__FILE__, __LINE__, kurisu::Logger::LogLevel::ERROR).stream()
#define LOG_FATAL kurisu::Logger(__FILE__, __LINE__, kurisu::Logger::LogLevel::FATAL).stream()
#define LOG_SYSERR kurisu::Logger(__FILE__, __LINE__, false).stream()
#define LOG_SYSFATAL kurisu::Logger(__FILE__, __LINE__, true).stream()


    // Check that the input is non NULL.  This very useful in constructor
    // initializer lists.
#define CHECK_NOTNULL(val) \
    kurisu::CheckNotNull(__FILE__, __LINE__, "'" #val "' Must be non NULL", (val))

    // A small helper for CHECK_NOTNULL().
    template <typename T>
    T* CheckNotNull(std::string_view file, int line, const char* names, T* ptr)
    {
        if (ptr == NULL)
            Logger(file, line, Logger::LogLevel::FATAL).stream() << names;
        return ptr;
    }
}  // namespace kurisu