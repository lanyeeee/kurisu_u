#include "copyable.hpp"
#include "boost/operators.hpp"
#include <chrono>
#include <fmt/chrono.h>

namespace ava {
    class TimeStamp : copyable,
                      public boost::less_than_comparable<TimeStamp>,
                      public boost::equality_comparable<TimeStamp> {
    public:
        TimeStamp() : stamp(std::chrono::system_clock::now()) {}
        TimeStamp(std::chrono::system_clock::time_point stamp) : stamp(stamp) {}

        auto GetStamp() const { return stamp; }
        void swap(TimeStamp& other) { std::swap(stamp, other.stamp); }
        std::string FormatString();
        int64_t usSinceEpoch();
        int64_t secondsSinceEpoch();

        static TimeStamp now();

    private:
        std::chrono::system_clock::time_point stamp;
    };

    inline std::string TimeStamp::FormatString() { return fmt::format("{:%Y-%m-%d %H:%M:%S}", fmt::localtime(stamp)); }
    inline TimeStamp TimeStamp::now() { return std::chrono::system_clock::now(); }
    inline bool operator<(TimeStamp& a, TimeStamp& b) { return a.GetStamp() < b.GetStamp(); }
    inline bool operator==(TimeStamp& a, TimeStamp& b) { return a.GetStamp() == b.GetStamp(); }
    inline int64_t TimeStamp::usSinceEpoch()
    {
        using namespace std::chrono;
        return duration_cast<microseconds>(stamp.time_since_epoch()).count();
    }
    inline int64_t TimeStamp::secondsSinceEpoch()
    {
        using namespace std::chrono;
        return duration_cast<seconds>(stamp.time_since_epoch()).count();
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