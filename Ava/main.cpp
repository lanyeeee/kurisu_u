#include <iostream>
#include <sys/time.h>
#include "time_stamp.hpp"
#include <thread>

class Timer {
private:
    std::chrono::steady_clock::time_point now;

public:
    Timer() : now(std::chrono::steady_clock::now()) {}
    void Print()
    {
        using namespace std::chrono;
        std::cout << duration_cast<milliseconds>(steady_clock::now() - now).count() << "ms" << std::endl;
        Mark();
    }
    void Mark() { now = std::chrono::steady_clock::now(); }
};


int main()
{
    using namespace std::chrono_literals;
    ava::TimeStamp time1;
    std::this_thread::sleep_for(2s);
    ava::TimeStamp time2;
    std::cout << ava::TimeDifference(time2, time1) << std::endl;
}