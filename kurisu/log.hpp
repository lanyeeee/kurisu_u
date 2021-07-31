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

}  // namespace kurisu