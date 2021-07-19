#pragma once
#include "detail/copyable.hpp"
#include <boost/operators.hpp>
#include <chrono>
#include <fmt/chrono.h>

namespace kurisu {
    class Timestamp : copyable,
                      public boost::less_than_comparable<Timestamp>,
                      public boost::equality_comparable<Timestamp> {
    public:
        Timestamp() : m_stamp(std::chrono::system_clock::now()) {}
        explicit Timestamp(std::chrono::system_clock::time_point stamp) : m_stamp(stamp) {}

        auto GetStamp() const { return m_stamp; }
        void swap(Timestamp& other) { std::swap(m_stamp, other.m_stamp); }
        bool valid() { return m_stamp != m_invalid; }
        char* GmLogFormat(char* buf) const { return fmt::format_to(buf, "{:%F %T} ", fmt::gmtime(m_stamp)); }
        char* LocalLogFormat(char* buf) const { return fmt::format_to(buf, "{:%F %T} ", fmt::localtime(m_stamp)); }
        //format gmtime
        std::string GmFormatString() const { return fmt::format("{:%F %T}", fmt::gmtime(m_stamp)); }
        //format localtime
        std::string LocalFormatString() const { return fmt::format("{:%F %T}", fmt::localtime(m_stamp)); }
        int64_t usSinceEpoch() const;
        int64_t nsSinceEpoch() const;
        int64_t secondsSinceEpoch() const;
        time_t as_time_t() { return (time_t)secondsSinceEpoch(); }

        static Timestamp now() { return Timestamp(std::chrono::system_clock::now()); }
        static Timestamp invalid() { return Timestamp(m_invalid); }

    private:
        static std::chrono::system_clock::time_point m_invalid;
        std::chrono::system_clock::time_point m_stamp;
    };
    inline std::chrono::system_clock::time_point Timestamp::m_invalid;

    inline bool operator<(Timestamp& a, Timestamp& b) { return a.GetStamp() < b.GetStamp(); }
    inline bool operator==(Timestamp& a, Timestamp& b) { return a.GetStamp() == b.GetStamp(); }
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
}  // namespace kurisu