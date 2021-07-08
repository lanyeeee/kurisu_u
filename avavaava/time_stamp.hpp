#pragma once
#include "copyable.hpp"
#include "boost/operators.hpp"
#include <chrono>
#include <fmt/chrono.h>

namespace ava {
    class TimeStamp : copyable,
                      public boost::less_than_comparable<TimeStamp>,
                      public boost::equality_comparable<TimeStamp> {
    public:
        TimeStamp() : m_stamp(std::chrono::system_clock::now()) {}
        explicit TimeStamp(std::chrono::system_clock::time_point stamp) : m_stamp(stamp) {}

        auto GetStamp() const { return m_stamp; }
        void swap(TimeStamp& other) { std::swap(m_stamp, other.m_stamp); }
        std::string FormatString();
        int64_t usSinceEpoch();
        int64_t secondsSinceEpoch();

        static TimeStamp now();

    private:
        std::chrono::system_clock::time_point m_stamp;
    };

    inline std::string TimeStamp::FormatString() { return fmt::format("{:%Y-%m-%d %H:%M:%S}", fmt::localtime(m_stamp)); }
    inline TimeStamp TimeStamp::now() { return TimeStamp(std::chrono::system_clock::now()); }
    inline bool operator<(TimeStamp& a, TimeStamp& b) { return a.GetStamp() < b.GetStamp(); }
    inline bool operator==(TimeStamp& a, TimeStamp& b) { return a.GetStamp() == b.GetStamp(); }
    inline int64_t TimeStamp::usSinceEpoch()
    {
        using namespace std::chrono;
        return duration_cast<microseconds>(m_stamp.time_since_epoch()).count();
    }
    inline int64_t TimeStamp::secondsSinceEpoch()
    {
        using namespace std::chrono;
        return duration_cast<seconds>(m_stamp.time_since_epoch()).count();
    }

    //seconds
    inline double TimeDifference(TimeStamp high, TimeStamp low)
    {
        using namespace std::chrono;
        auto a = duration_cast<microseconds>(high.GetStamp().time_since_epoch()).count();
        auto b = duration_cast<microseconds>(low.GetStamp().time_since_epoch()).count();
        return (double)(a - b) / 1'000'000;
    }
}  // namespace ava