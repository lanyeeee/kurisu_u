#include "thread.hpp"
#include "log.hpp"
#include "time_stamp.hpp"
#include <map>
#include <set>
#include <iostream>
#include "detail/socket.hpp"
#include "detail/buffer.hpp"
#include <algorithm>
#include "event_loop.hpp"
#include <memory>



std::mutex muMap;
std::map<uint64_t, uint64_t> map;
int g = 0;
int r = rand() % 100;

void Fn(int num)
{
    g += num % r;
}

void Fn()
{
    g += rand() % 100;
}


void Func()
{
    for (int i = 0; i < 1000000; i++)
    {
        kurisu::Timestamp t;
        auto start = kurisu::Timestamp::now().nsSinceEpoch();
        Fn();
        auto end = kurisu::Timestamp::now().nsSinceEpoch();
        int64_t d = end - start;
        std::lock_guard locker(muMap);
        if (d < 1000)
            map[d]++;
    }
    for (auto&& item : map)
        std::cout << item.first << ":" << item.second << std::endl;
    std::cout << g << std::endl;
}



int main()
{
    kurisu::Timestamp::now();
    Func();
}


















// #include "detail/buffer.hpp"
// #include <set>
// #include <map>
// #include <iostream>
// #include <memory>
// #include "event_loop.hpp"

// class Entity : boost::totally_ordered<Entity> {
// public:
//     int64_t x;
//     Entity(int x) : x(x) { std::cout << "cons\n"; }
//     ~Entity() { std::cout << "des\n"; }
//     friend bool operator<(Entity a, Entity b) { return a.x < b.x; }
//     friend bool operator==(Entity a, Entity b) { return a.x == b.x; }
// };

// int g = 0;

// void Fn(uint64_t num)
// {
//     g += num % 100;
// }

// void Fn()
// {
//     g += rand() % 100;
// }

// int main()
// {
//         Entity b(2);
// }
