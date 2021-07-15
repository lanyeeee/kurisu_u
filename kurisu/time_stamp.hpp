#pragma once
#include <boost/operators.hpp>
#include <chrono>
#include <fmt/chrono.h>
#include "copyable.hpp"

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
        std::string FormatString();
        int64_t usSinceEpoch();
        int64_t secondsSinceEpoch();

        static Timestamp now() { return Timestamp(std::chrono::system_clock::now()); }
        static Timestamp invalid() { return Timestamp(m_invalid); }

    private:
        static std::chrono::system_clock::time_point m_invalid;
        std::chrono::system_clock::time_point m_stamp;
    };
    inline std::chrono::system_clock::time_point Timestamp::m_invalid;

    inline bool operator<(Timestamp& a, Timestamp& b) { return a.GetStamp() < b.GetStamp(); }
    inline bool operator==(Timestamp& a, Timestamp& b) { return a.GetStamp() == b.GetStamp(); }
    inline std::string Timestamp::FormatString()
    {
        char buf[64];
        fmt::format_to(buf, "{:%Y-%m-%d %H:%M:%S}", fmt::localtime(m_stamp));
        return buf;
    }
    inline int64_t Timestamp::usSinceEpoch()
    {
        using namespace std::chrono;
        return duration_cast<microseconds>(m_stamp.time_since_epoch()).count();
    }
    inline int64_t Timestamp::secondsSinceEpoch()
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