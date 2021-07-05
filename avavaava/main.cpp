// #include <iostream>
// #include <sys/time.h>
// #include "time_stamp.hpp"
// #include <thread>

// class Timer {
// private:
//     std::chrono::steady_clock::time_point now;

// public:
//     Timer() : now(std::chrono::steady_clock::now()) {}
//     void Print()
//     {
//         using namespace std::chrono;
//         std::cout << duration_cast<milliseconds>(steady_clock::now() - now).count() << "ms" << std::endl;
//         Mark();
//     }
//     void Mark() { now = std::chrono::steady_clock::now(); }
// };


// int main()
// {
//     using namespace std::chrono_literals;
//     ava::TimeStamp time1;
//     std::this_thread::sleep_for(2s);
//     ava::TimeStamp time2;
//     std::cout << ava::TimeDifference(time2, time1) << std::endl;
// }


#include "muduo/base/Timestamp.h"
#include <vector>
#include <stdio.h>
#include <iostream>
#include "time_stamp.hpp"

using muduo::Timestamp;

void passByConstReference(const Timestamp& x)
{
    printf("%s\n", x.toString().c_str());
}

void passByValue(Timestamp x)
{
    printf("%s\n", x.toString().c_str());
}

void benchmark()
{
    const int kNumber = 1000 * 1000;

    std::vector<Timestamp> stamps;
    stamps.reserve(kNumber);
    for (int i = 0; i < kNumber; ++i)
    {
        stamps.push_back(Timestamp::now());
    }
    printf("%s\n", stamps.front().toString().c_str());
    printf("%s\n", stamps.back().toString().c_str());
    printf("%f\n", timeDifference(stamps.back(), stamps.front()));

    int increments[100] = {0};
    int64_t start = stamps.front().microSecondsSinceEpoch();
    for (int i = 1; i < kNumber; ++i)
    {
        int64_t next = stamps[i].microSecondsSinceEpoch();
        int64_t inc = next - start;
        start = next;
        if (inc < 0)
        {
            printf("reverse!\n");
        }
        else if (inc < 100)
        {
            ++increments[inc];
        }
        else
        {
            printf("big gap %d\n", static_cast<int>(inc));
        }
    }

    for (int i = 0; i < 100; ++i)
    {
        printf("%2d: %d\n", i, increments[i]);
    }
}

void Func()
{
    const int kNumber = 1000 * 1000;

    std::vector<ava::TimeStamp> stamps;
    stamps.reserve(kNumber);
    for (int i = 0; i < kNumber; ++i)
    {
        stamps.push_back(ava::TimeStamp::now());
    }
    printf("%f\n", ava::TimeDifference(stamps.back(), stamps.front()));

    int increments[100] = {0};
    int64_t start = stamps.front().usSinceEpoch();
    for (int i = 1; i < kNumber; ++i)
    {
        int64_t next = stamps[i].usSinceEpoch();
        int64_t inc = next - start;
        start = next;
        if (inc < 0)
        {
            printf("reverse!\n");
        }
        else if (inc < 100)
        {
            ++increments[inc];
        }
        else
        {
            printf("big gap %d\n", static_cast<int>(inc));
        }
    }

    for (int i = 0; i < 100; ++i)
    {
        printf("%2d: %d\n", i, increments[i]);
    }
}

int main()
{
    // Timestamp now(Timestamp::now());
    // printf("%s\n", now.toString().c_str());
    // passByValue(now);
    // passByConstReference(now);
    benchmark();
    std::cout << "-----------------------------\n";
    Func();
}
