// #include <iostream>
// #include <chrono>
// #include <vector>
// #include <memory>
// #include <mutex>
// #include <map>
// #include <string.h>
// #include <sys/time.h>
// #include <time.h>
// #include <muduo/base/Timestamp.h>
// #include <future>
// #include <list>
// #include <boost/circular_buffer.hpp>
// #include <unordered_set>
// #include <set>

// std::mutex muMap;
// std::map<uint64_t, uint64_t> map;

// const int LEN = 1000;
// uint64_t g;

// class Entity : public std::enable_shared_from_this<Entity> {
// public:
//     void Func(const std::shared_ptr<Entity>& conn)
//     {
//         std::cout << conn.use_count() << std::endl;
//     }
// };


// void Func()
// {
//     for (int i = 0; i < 10000; i++)
//     {
//         std::set<uint64_t> set;
//         std::unordered_set<uint64_t> uset;
//         auto start = std::chrono::system_clock::now().time_since_epoch().count();
//         for (int i = 0; i < 1000; i++)
//             set.insert(i);
//         auto end = std::chrono::system_clock::now().time_since_epoch().count();
//         int64_t d = end - start;
//         std::lock_guard locker(muMap);
//         if (d < 30000)
//             map[d]++;
//         g = set.size();
//     }
//     for (auto&& item : map)
//         std::cout << item.first << ":" << item.second << std::endl;
//     std::cout << "result=" << g << std::endl;
// }



// int main()
// {
//     Func();
//     std::cout << "finish\n";
// }



















#include "all.hpp"
// kurisu::AsyncLogFile logger("hh", 100 * 1024 * 1024, 1);

int main()
{
    kurisu::Logger::SetTimeZone(1);
    // kurisu::Logger::SetOutput([](const char* msg, uint64_t len) { logger.append(msg, len); });
    kurisu::EventLoop loop;

    kurisu::TcpServer serv(&loop, kurisu::SockAddr(5005), "serv");
    serv.SetConnectionCallback([](const std::shared_ptr<kurisu::TcpConnection>& conn) {
        if (conn->Connected())
            conn->GetLoop()->AddToTimingWheel(conn);
    });
    serv.SetMessageCallback([](const std::shared_ptr<kurisu::TcpConnection>& conn, kurisu::Buffer* buf, kurisu::Timestamp) {
        conn->Send(buf);
        conn->GetLoop()->UpdateTimingWheel(conn);
    });
    serv.SetTimingWheel(5);
    serv.SetThreadNum(4);
    serv.Start();
    loop.Loop();
}



















// #include "all.hpp"
// #include <iostream>
// #include <aio.h>

// int main()
// {
//     int listenfd = kurisu::detail::MakeNonblockingSocket(AF_INET);
//     kurisu::SockAddr addr(5005);

//     kurisu::detail::Socket listensock(listenfd);
//     listensock.SetReuseAddr(1);
//     listensock.bind(&addr);
//     listensock.listen();
//     kurisu::SockAddr peer;

//     kurisu::this_thrd::SleepFor(2'000'000);
//     int clientfd = listensock.accept(&peer);
//     int nZero = 0;
//     setsockopt(clientfd, SOL_SOCKET, SO_SNDBUF, (char*)&nZero, sizeof(nZero));
//     const int LEN = 1024;
//     char buf[LEN] = {0};

//     kurisu::Buffer buffer(1025);
//     int epollfd = epoll_create(1);
//     epoll_event ev;
//     ev.data.fd = clientfd;
//     ev.events = EPOLLIN;
//     int n = 0;
//     int saveErrno;
//     epoll_ctl(epollfd, EPOLL_CTL_ADD, clientfd, &ev);

//     std::vector<int*> vec;
//     vec.reserve(8);
//     std::string str = "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh";
//     for (int i = 0; i < 20; i++)
//         str += str;
//     std::cout << str.size();

//     kurisu::Timestamp start1;
//     n = read(clientfd, buf, LEN);
//     kurisu::Timestamp end1;



//     kurisu::Timestamp start2;
//     n = write(clientfd, buf, LEN);
//     kurisu::Timestamp end2;



//     kurisu::Timestamp start3;
//     n = write(clientfd, buf, LEN);
//     kurisu::Timestamp end3;



//     kurisu::Timestamp start4;
//     n = write(clientfd, buf, LEN);
//     kurisu::Timestamp end4;



//     kurisu::Timestamp start5;
//     n = write(clientfd, buf, LEN);
//     kurisu::Timestamp end5;



//     kurisu::Timestamp start6;
//     n = write(clientfd, str.data(), str.size());
//     kurisu::Timestamp end6;



//     kurisu::Timestamp start7;
//     n = write(clientfd, str.data(), str.size());
//     kurisu::Timestamp end7;



//     kurisu::Timestamp start8;

//     kurisu::Timestamp end8;



//     kurisu::Timestamp start9;

//     kurisu::Timestamp end9;

//     std::cout << "1 " << end1.nsSinceEpoch() - start1.nsSinceEpoch() << "ns" << std::endl;
//     std::cout << "2 " << end2.nsSinceEpoch() - start2.nsSinceEpoch() << "ns" << std::endl;
//     std::cout << "3 " << end3.nsSinceEpoch() - start3.nsSinceEpoch() << "ns" << std::endl;
//     std::cout << "4 " << end4.nsSinceEpoch() - start4.nsSinceEpoch() << "ns" << std::endl;
//     std::cout << "5 " << end5.nsSinceEpoch() - start5.nsSinceEpoch() << "ns" << std::endl;
//     std::cout << "6 " << end6.nsSinceEpoch() - start6.nsSinceEpoch() << "ns" << std::endl;
//     std::cout << "7 " << end7.nsSinceEpoch() - start7.nsSinceEpoch() << "ns" << std::endl;
//     std::cout << "8 " << end8.nsSinceEpoch() - start8.nsSinceEpoch() << "ns" << std::endl;
//     std::cout << "9 " << end9.nsSinceEpoch() - start9.nsSinceEpoch() << "ns" << std::endl;
//     std::cout << "errno=" << errno << std::endl;
//     std::cout << "n=" << n << std::endl;
//     std::cout << buf << std::endl;
// }




























// // // #include <muduo/net/TcpServer.h>
// // // #include <muduo/net/EventLoop.h>
// // // #include <muduo/base/Logging.h>
// // // #include <muduo/net/EventLoopThreadPool.h>
// // // #include <atomic>
// // // using namespace muduo;
// // // using namespace muduo::net;


// // // int main()
// // // {
// // //     EventLoop loop;
// // //     TcpServer serv(&loop, InetAddress(5005), "serv");
// // //     serv.setMessageCallback([](const TcpConnectionPtr& conn, Buffer* buf, Timestamp time) {
// // //         conn->send(buf);
// // //     });
// // //     serv.setThreadNum(4);
// // //     serv.start();
// // //     loop.loop();
// // // }



// #include "all.hpp"
// #include "boost/circular_buffer.hpp"
// #include "CircularBuffer.hpp"

// class Entity {
// public:
//     Entity() = default;
//     Entity(const Entity&) { LOG_INFO << "COPY"; }
//     Entity(Entity&&) { LOG_INFO << "MOVE"; }
// };

// void Func()
// {
//     CircularBuffer<int> buf(3);
//     // auto p1 = std::make_shared<Entity>();
//     // auto p2 = std::make_shared<Entity>();
//     // auto p3 = std::make_shared<Entity>();
//     // auto p4 = std::make_shared<Entity>();

//     buf.push_back(1);
//     buf.push_back(2);
//     buf.push_back(3);
//     // LOG_INFO << "p1=" << p1.use_count();
//     // LOG_INFO << "p2=" << p2.use_count();
//     // LOG_INFO << "p3=" << p3.use_count();
//     // LOG_INFO << "p4=" << p4.use_count();
//     for (int i = 0; i < 3; i++)
//         LOG_WARN << buf.m_vec[i];
//     LOG_INFO << "==========";
//     buf.push_back(4);
//     buf.push_back(5);
//     buf.push_front(4);
//     buf.push_front(4);
//     buf.push_front(4);
//     for (int i = 0; i < 3; i++)
//         LOG_WARN << buf.m_vec[i];
//     // LOG_INFO << "p1=" << p1.use_count();
//     // LOG_INFO << "p2=" << p2.use_count();
//     // LOG_INFO << "p3=" << p3.use_count();
//     // LOG_INFO << "p4=" << p4.use_count();
// }

// int main()
// {
//     Func();
//     LOG_INFO << "finish";
// }