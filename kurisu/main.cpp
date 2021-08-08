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
// int g = 0;
// int r = rand() % 100;

// void Fn(int num)
// {
//     g += num % r;
// }

// void Fn()
// {
//     g += rand() % 100;
// }


// void Func()
// {
//     for (int i = 0; i < 1000000; i++)
//     {
//         kurisu::Timestamp t;
//         auto start = kurisu::Timestamp::now().nsSinceEpoch();
//         Fn();
//         auto end = kurisu::Timestamp::now().nsSinceEpoch();
//         int64_t d = end - start;
//         std::lock_guard locker(muMap);
//         if (d < 1000)
//             map[d]++;
//     }
//     for (auto&& item : map)
//         std::cout << item.first << ":" << item.second << std::endl;
//     std::cout << g << std::endl;
// }



// int main()
// {
//     kurisu::Timestamp::now();
//     Func();
// }



















#include "all.hpp"

int main()
{
    kurisu::EventLoop loop;
    kurisu::TcpServer serv(&loop, kurisu::SockAddr(5005), "serv");
    serv.setMessageCallback([](const std::shared_ptr<kurisu::TcpConnection>& conn, kurisu::Buffer* buf, kurisu::Timestamp) {
        conn->send(buf);
    });
    serv.setThreadNum(4);
    serv.start();
    loop.loop();
}
























// #include <muduo/net/TcpServer.h>
// #include <muduo/net/EventLoop.h>
// #include <muduo/base/ProcessInfo.h>
// #include <muduo/base/Logging.h>
// using namespace muduo;
// using namespace muduo::net;

// int main()
// {
//     EventLoop loop;
//     TcpServer serv(&loop, InetAddress(5005), "serv");
//     serv.setMessageCallback([](const TcpConnectionPtr& conn, Buffer* buf, Timestamp time) {
//         conn->send(buf);
//     });
//     serv.setThreadNum(4);
//     serv.start();
//     sleep(2);
//     LOG_WARN << muduo::ProcessInfo::cpuTime().total();
//     loop.loop();
// }