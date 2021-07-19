#include "thread.hpp"
#include "log.hpp"
#include "time_stamp.hpp"
#include <map>
#include <iostream>

std::map<uint64_t, uint64_t> map;
std::mutex muMap;


void Func()
{
    for (int i = 0; i < 1000000; i++)
    {
        kurisu::Timestamp t;
        auto start = kurisu::Timestamp::now().nsSinceEpoch();

        auto end = kurisu::Timestamp::now().nsSinceEpoch();
        int64_t d = end - start;
        std::lock_guard locker(muMap);
        if (d < 3000)
            map[d]++;
    }
}


int main()
{
    Func();
    for (auto&& item : map)
        std::cout << item.first << ":" << item.second << std::endl;
}
