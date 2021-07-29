#pragma once
#include "detail/copyable.hpp"
#include <boost/operators.hpp>
#include <chrono>
#include <fmt/chrono.h>
#include <fmt/compile.h>

namespace kurisu {
    class Timestamp : copyable,
                      public boost::less_than_comparable<Timestamp>,
                      public boost::equality_comparable<Timestamp> {
    public:
        Timestamp() : m_stamp(std::chrono::system_clock::now()) {}
        explicit Timestamp(std::chrono::system_clock::time_point stamp) : m_stamp(stamp) {}

        auto GetStamp() const { return m_stamp; }
        void swap(Timestamp& other) { std::swap(m_stamp, other.m_stamp); }
        bool valid() { return m_stamp != s_invalid; }
        char* GmLogFormat(char* buf) const
        {
            uint64_t us = usSinceEpoch() - secondsSinceEpoch() * 1'000'000;
            return fmt::format_to(buf, FMT_COMPILE("[{:%F %T}.{:06}] "), fmt::gmtime(m_stamp), us);
        }
        char* LocalLogFormat(char* buf) const
        {
            uint64_t us = usSinceEpoch() - secondsSinceEpoch() * 1'000'000;
            return fmt::format_to(buf, FMT_COMPILE("[{:%F %T}.{:06}] "), fmt::localtime(m_stamp), us);
        }
        //format gmtime
        std::string GmFormatString() const { return fmt::format(FMT_COMPILE("{:%F %T}"), fmt::gmtime(m_stamp)); }
        //format localtime
        std::string LocalFormatString() const { return fmt::format(FMT_COMPILE("{:%F %T}"), fmt::localtime(m_stamp)); }
        int64_t usSinceEpoch() const;
        int64_t nsSinceEpoch() const;
        int64_t secondsSinceEpoch() const;
        time_t as_time_t() { return (time_t)secondsSinceEpoch(); }

        static Timestamp now() { return Timestamp(std::chrono::system_clock::now()); }
        static Timestamp invalid() { return Timestamp(s_invalid); }

    private:
        static std::chrono::system_clock::time_point s_invalid;
        std::chrono::system_clock::time_point m_stamp;
    };
    inline std::chrono::system_clock::time_point Timestamp::s_invalid;

    inline bool operator<(Timestamp a, Timestamp b) { return a.GetStamp() < b.GetStamp(); }
    inline bool operator==(Timestamp a, Timestamp b) { return a.GetStamp() == b.GetStamp(); }
    inline int64_t Timestamp::usSinceEpoch() const
    {
        using namespace std::chrono;
        return duration_cast<microseconds>(m_stamp.time_since_epoch()).count();
    }
    inline int64_t Timestamp::nsSinceEpoch() const
    {
        using namespace std::chrono;
        return duration_cast<nanoseconds>(m_stamp.time_since_epoch()).count();
    }
    inline int64_t Timestamp::secondsSinceEpoch() const
    {
        using namespace std::chrono;
        return duration_cast<seconds>(m_stamp.time_since_epoch()).count();
    }

    //seconds
    inline double TimeDifference(Timestamp high, Timestamp low)
    {
        using namespace std::chrono;
        auto a = duration_cast<microseconds>(high.GetStamp().time_since_epoch()).count();
        auto b = duration_cast<microseconds>(low.GetStamp().time_since_epoch()).count();
        return (double)(a - b) / 1'000'000;
    }

    inline Timestamp AddTime(Timestamp stamp, double second)
    {
        using namespace std::chrono;
        uint64_t s = (uint64_t)second;
        uint64_t us = (uint64_t)((second - (double)s) * 1'000'000);
        return Timestamp(stamp.GetStamp() + seconds(s) + microseconds(us));
    }

}  // namespace kurisu