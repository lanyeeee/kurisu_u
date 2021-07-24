#pragma once
#include <string.h>
#include "log_stream.hpp"
#include "known_length_string.hpp"
#include "thrd.hpp"
#include "../time_stamp.hpp"

namespace kurisu {
    namespace detail {
        inline __thread char t_errnobuf[512];
        inline __thread char t_time[64];
        inline __thread int64_t t_lastSecond;

        inline const char* strerror_tl(int savedErrno) { return strerror_r(savedErrno, t_errnobuf, sizeof(t_errnobuf)); }
    }  // namespace detail

    class Logger {
    public:
        enum class LogLevel {
            TRACE,
            DEBUG,
            INFO,
            WARN,
            ERROR,
            FATAL,
        };
        Logger(const std::string_view& file, int line);
        Logger(const std::string_view& file, int line, LogLevel level);
        Logger(const std::string_view& file, int line, LogLevel level, const char* func);
        Logger(const std::string_view& file, int line, bool toAbort);
        ~Logger();

        LogStream& stream() { return m_fmt.m_strm; }
        static LogLevel level();

        class SetLogLevel;

        //using OutputFunc = void (*)(const char* msg, const uint64_t len);
        //using FlushFunc = void (*)();
        static void SetOutput(void (*)(const char* msg, const uint64_t len));
        static void SetFlush(void (*)());
        static void SetTimeZone(bool isLocal) { m_isLocalTimeZone = isLocal; }

    private:
        class Formatter {
        public:
            using LogLevel = Logger::LogLevel;
            Formatter(LogLevel level, int old_errno, std::string_view file, int line);
            void FormatTime();
            void Finish();

            Timestamp m_time;
            LogStream m_strm;
            LogLevel m_level;
            int m_line;
            const char* m_fileName;
            uint64_t m_fileNameSize;
        };
        static bool m_isLocalTimeZone;
        Formatter m_fmt;
    };
    inline bool Logger::m_isLocalTimeZone = false;
}  // namespace kurisu


namespace kurisu {
    namespace detail {
        inline void DefaultOutput(const char* msg, const uint64_t len) { fwrite(msg, 1, len, stdout); }
        inline void DefaultFlush() { fflush(stdout); }
        inline Logger::LogLevel InitLogLevel()
        {
            if (getenv("KURISU_LOG_TRACE"))
                return Logger::LogLevel::TRACE;
            else if (getenv("KURISU_LOG_DEBUG"))
                return Logger::LogLevel::DEBUG;
            else
                return Logger::LogLevel::INFO;
        }

        inline void (*g_output)(const char* msg, const uint64_t len) = DefaultOutput;
        inline void (*g_flush)() = DefaultFlush;
        inline Logger::LogLevel g_logLevel = InitLogLevel();
        inline const char* LogLevelName[6] = {
            "[TRACE] ",
            "[DEBUG] ",
            "[INFO]  ",
            "[WARN]  ",
            "[ERROR] ",
            "[FATAL] ",
        };

    }  // namespace detail

    inline Logger::Formatter::Formatter(LogLevel level, int savedErrno, std::string_view file, int line)
        : m_time(Timestamp::now()), m_strm(), m_level(level), m_line(line)
    {
        if (auto slash = file.rfind('/'); slash != std::string_view::npos)
        {
            file = file.substr(slash + 1);
            m_fileName = file.data();
        }
        m_fileNameSize = file.size();

        FormatTime();
        this_thrd::tid();
        m_strm << '[' << KnownLengthString(this_thrd::TidString(), this_thrd::TidStringLength()) << ']' << " ";
        m_strm << KnownLengthString(detail::LogLevelName[(int)level], 8);
        if (savedErrno != 0)
            m_strm << detail::strerror_tl(savedErrno) << " (errno=" << savedErrno << ") ";
    }
    inline void Logger::Formatter::FormatTime()
    {
        using namespace detail;
        static KnownLengthString timeString(t_time, 0);
        char* p = nullptr;

        if (m_time.secondsSinceEpoch() != t_lastSecond)
        {
            t_lastSecond = m_time.secondsSinceEpoch();
            if (!m_isLocalTimeZone)
                p = m_time.GmLogFormat(t_time);
            else
                p = m_time.LocalLogFormat(t_time);
        }

        if (p)
            timeString = KnownLengthString(t_time, p - t_time);

        m_strm << timeString;
    }
    inline void Logger::Formatter::Finish()
    {
        m_strm << " - " << KnownLengthString(m_fileName, m_fileNameSize) << ':' << m_line << '\n';
    }


    inline Logger::Logger(const std::string_view& file, int line) : m_fmt(LogLevel::INFO, 0, file, line) {}
    inline Logger::Logger(const std::string_view& file, int line, LogLevel level, const char* func)
        : m_fmt(level, 0, file, line) { m_fmt.m_strm << func << ' '; }
    inline Logger::Logger(const std::string_view& file, int line, LogLevel level) : m_fmt(level, 0, file, line) {}
    inline Logger::Logger(const std::string_view& file, int line, bool toAbort)
        : m_fmt(toAbort ? LogLevel::FATAL : LogLevel::ERROR, errno, file, line) {}
    inline Logger::~Logger()
    {
        using namespace std::chrono;
        m_fmt.Finish();

        const LogStream::Buf& buf(stream().buffer());

        detail::g_output(buf.data(), buf.size());

        if (m_fmt.m_level == LogLevel::FATAL)
        {
            detail::g_flush();
            abort();
        }
    }
    inline Logger::LogLevel Logger::level() { return detail::g_logLevel; }
    inline void Logger::SetOutput(void (*out)(const char* msg, const uint64_t len)) { detail::g_output = out; }
    inline void Logger::SetFlush(void (*flush)()) { detail::g_flush = flush; }

    class Logger::SetLogLevel {
    public:
        static void TRACE() { detail::g_logLevel = Logger::LogLevel::TRACE; }
        static void DEBUG() { detail::g_logLevel = Logger::LogLevel::DEBUG; }
        static void INFO() { detail::g_logLevel = Logger::LogLevel::INFO; }
        static void WARN() { detail::g_logLevel = Logger::LogLevel::WARN; }
        static void ERROR() { detail::g_logLevel = Logger::LogLevel::ERROR; }
        static void FATAL() { detail::g_logLevel = Logger::LogLevel::FATAL; }
    };

}  // namespace kurisu
