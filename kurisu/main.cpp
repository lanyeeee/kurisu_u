// #include "detail/down_cast.hpp"
// #include "thread.hpp"
// #include "log.hpp"
// #include "time_stamp.hpp"
// #include <map>
// #include <set>
// #include <iostream>
// #include "detail/socket.hpp"
// #include "detail/buffer.hpp"
// #include <algorithm>
// #include "event_loop.hpp"
// #include <memory>



// std::mutex muMap;
// std::map<uint64_t, uint64_t> map;


// void Func()
// {
//     std::set<std::pair<int, std::unique_ptr<int>>> set1;
//     std::map<std::pair<int, int*>, std::unique_ptr<int>> map1;
//     int* ptr;
//     for (int i = 0; i < 1000000; i++)
//     {
//         auto p = std::make_unique<int>(i);
//         ptr = p.get();
//         map1[std::make_pair(i, p.get())] = std::move(p);
//         // set1.emplace(i, std::move(p));
//     }

//     for (int i = 0; i < 1000000; i++)
//     {
//         kurisu::Timestamp t;
//         auto start = kurisu::Timestamp::now().nsSinceEpoch();
//         auto res = map1.find(std::make_pair(i, ptr));
//         auto end = kurisu::Timestamp::now().nsSinceEpoch();
//         int64_t d = end - start;
//         std::lock_guard locker(muMap);
//         if (d < 1000)
//             map[d]++;
//     }
//     for (auto&& item : map)
//         std::cout << item.first << ":" << item.second << std::endl;
// }



// int main()
// {
//     Func();
// }


















// #include "time_stamp.hpp"
// #include <set>
// #include <map>
// #include <iostream>
// #include <memory>

// class Entity {
// public:
//     int x = 0;
//     Entity(int x) : x(x) { std::cout << "cons\n"; }
//     ~Entity() { std::cout << "des\n"; }
//     bool operator<(const Entity& e) const { return x < e.x; }
// };

// int main()
// {
//     std::vector<int> vec;
//     vec.push_back(1);
//     vec.push_back(1);
//     vec.push_back(1);
//     vec.push_back(1);
//     vec.push_back(1);
//     std::cout << std::distance(vec.end(), vec.begin());
//     std::cout << "haha\n";
// }




































#include "event_loop.hpp"

#include <stdio.h>
#include <unistd.h>

using namespace kurisu;

int cnt = 0;
EventLoop* g_loop;

void printTid()
{
    printf("pid = %d, tid = %d\n", getpid(), this_thrd::tid());
    char buf[64] = {0};
    Timestamp::now().LocalLogFormat(buf);
    printf("now %s\n", buf);
}

void print(const char* msg)
{
    char buf[64] = {0};
    Timestamp::now().LocalLogFormat(buf);
    printf("msg %s %s\n", buf, msg);
    if (++cnt == 20)
    {
        g_loop->quit();
    }
}

void cancel(TimerID timer)
{
    g_loop->cancel(timer);
    char buf[64] = {0};
    Timestamp::now().LocalLogFormat(buf);
    printf("cancelled at %s\n", buf);
}

int main()
{
    printTid();
    sleep(1);
    {
        EventLoop loop;
        g_loop = &loop;

        print("main");
        loop.runAfter(1, std::bind(print, "once1"));
        loop.runAfter(1.5, std::bind(print, "once1.5"));
        loop.runAfter(2.5, std::bind(print, "once2.5"));
        loop.runAfter(3.5, std::bind(print, "once3.5"));
        TimerID t45 = loop.runAfter(4.5, std::bind(print, "once4.5"));
        loop.runAfter(4.2, std::bind(cancel, t45));
        loop.runAfter(4.8, std::bind(cancel, t45));
        loop.runEvery(2, std::bind(print, "every2"));
        TimerID t3 = loop.runEvery(3, std::bind(print, "every3"));
        loop.runAfter(9.001, std::bind(cancel, t3));

        loop.loop();
        print("main loop exits");
    }
    sleep(1);
    {
        EventLoopThread loopThread;
        EventLoop* loop = loopThread.startLoop();
        loop->runAfter(2, printTid);
        sleep(3);
        print("thread loop exits");
    }
}
