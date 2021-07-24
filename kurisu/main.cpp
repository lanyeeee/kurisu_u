// // #include "detail/down_cast.hpp"
// // #include "thread.hpp"
// // #include "log.hpp"
// // #include "time_stamp.hpp"
// // #include <map>
// // #include <iostream>
// // #include "detail/socket.hpp"
// // #include "event_loop.hpp"
// // #include "thread.hpp"

// // std::mutex muMap;
// // std::map<uint64_t, uint64_t> map;


// // void Func()
// // {
// //     std::string str;
// //     for (int i = 0; i < 1000000; i++)
// //     {
// //         kurisu::Timestamp t;
// //         auto start = kurisu::Timestamp::now().nsSinceEpoch();

// //         auto end = kurisu::Timestamp::now().nsSinceEpoch();
// //         int64_t d = end - start;
// //         std::lock_guard locker(muMap);
// //         if (d < 3000)
// //             map[d]++;
// //     }
// //     for (auto&& item : map)
// //         std::cout << item.first << ":" << item.second << std::endl;
// //     std::cout << str << std::endl;
// // }



// // int main()
// // {
// //     Func();
// //     // const char* ip = "0.0.0.0";
// //     // uint16_t port = 5005;
// //     // int listenfd = kurisu::socket_func::MakeNonblockingSocket(AF_INET);
// //     // kurisu::socket_func::sockaddr_u addr;
// //     // kurisu::socket_func::IpProtToAddr(ip, port, &addr.sin);
// //     // kurisu::socket_func::BindAndListen(listenfd, &addr);
// //     // char buf[1024] = {0};
// // }










































// // #include "log.hpp"
// // #include "event_loop.hpp"

// // #include <functional>
// // #include <map>

// // #include <stdio.h>
// // #include <unistd.h>
// // #include <sys/timerfd.h>

// // using namespace kurisu;

// // void print(const char* msg)
// // {
// //     static std::map<const char*, Timestamp> lasts;
// //     Timestamp& last = lasts[msg];
// //     Timestamp now = Timestamp::now();
// //     printf("%s tid %d %s delay %f\n", now.GmFormatString().c_str(), this_thrd::tid(),
// //            msg, TimeDifference(now, last));
// //     last = now;
// // }

// // namespace kurisu {
// //     namespace net {
// //         namespace detail {
// //             int createTimerfd();
// //             void readTimerfd(int timerfd, Timestamp now);
// //         }  // namespace detail
// //     }      // namespace net
// // }  // namespace kurisu

// // // Use relative time, immunized to wall clock changes.
// // class PeriodicTimer {
// // public:
// //     PeriodicTimer(EventLoop* loop, double interval)
// //         : loop_(loop),
// //           timerfd_(kurisu::net::detail::createTimerfd()),
// //           timerfdChannel_(loop, timerfd_),
// //           interval_(interval)
// //     {
// //         timerfdChannel_.setReadCallback(
// //             std::bind(&PeriodicTimer::handleRead, this));
// //         timerfdChannel_.enableReading();
// //     }

// //     void start()
// //     {
// //         struct itimerspec spec;
// //         memset(&spec, 0, sizeof(spec));
// //         spec.it_interval = toTimeSpec(interval_);
// //         spec.it_value = spec.it_interval;
// //         int ret = ::timerfd_settime(timerfd_, 0 /* relative timer */, &spec, NULL);
// //         if (ret)
// //         {
// //             LOG_SYSERR << "timerfd_settime()";
// //         }
// //     }

// //     ~PeriodicTimer()
// //     {
// //         timerfdChannel_.disableAll();
// //         timerfdChannel_.remove();
// //         ::close(timerfd_);
// //     }

// // private:
// //     void handleRead()
// //     {
// //         kurisu::net::detail::readTimerfd(timerfd_, Timestamp::now());
// //     }

// //     static struct timespec toTimeSpec(double seconds)
// //     {
// //         struct timespec ts;
// //         memset(&ts, 0, sizeof(ts));
// //         const int64_t kNanoSecondsPerSecond = 1000000000;
// //         const int kMinInterval = 100000;
// //         int64_t nanoseconds = static_cast<int64_t>(seconds * kNanoSecondsPerSecond);
// //         if (nanoseconds < kMinInterval)
// //             nanoseconds = kMinInterval;
// //         ts.tv_sec = static_cast<time_t>(nanoseconds / kNanoSecondsPerSecond);
// //         ts.tv_nsec = static_cast<long>(nanoseconds % kNanoSecondsPerSecond);
// //         return ts;
// //     }

// //     EventLoop* loop_;
// //     const int timerfd_;
// //     Channel timerfdChannel_;
// //     const double interval_;  // in seconds
// // };

// // int main(int argc, char* argv[])
// // {
// //     LOG_INFO << "pid = " << getpid() << ", tid = " << this_thrd::tid()
// //              << " Try adjusting the wall clock, see what happens.";
// //     EventLoop loop;
// //     PeriodicTimer timer(&loop, 1, std::bind(print, "PeriodicTimer"));
// //     timer.start();
// //     loop.loop();
// // }



















// #include "event_loop.hpp"
// #include "log.hpp"

// #include <functional>
// #include <map>

// #include <stdio.h>
// #include <unistd.h>
// #include <sys/timerfd.h>

// using namespace kurisu;

// void print(const char* msg)
// {
//     static std::map<const char*, Timestamp> lasts;
//     Timestamp& last = lasts[msg];
//     Timestamp now = Timestamp::now();
//     printf("%s tid %d %s delay %f\n", now.GmFormatString().c_str(), this_thrd::tid(), msg, TimeDifference(now, last));
//     last = now;
// }

// namespace muduo {
//     namespace net {
//         namespace detail {
//             int createTimerfd() { return ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC); }
//             void readTimerfd(int timerfd, Timestamp now)
//             {
//                 uint64_t howmany;
//                 ssize_t n = read(timerfd, &howmany, sizeof howmany);
//                 LOG_TRACE << "TimerQueue::handleRead() " << howmany << " at " << now.GmFormatString();
//                 if (n != sizeof howmany)
//                 {
//                     LOG_ERROR << "TimerQueue::handleRead() reads " << n << " bytes instead of 8";
//                 }
//             }
//         }  // namespace detail
//     }      // namespace net
// }  // namespace muduo

// // Use relative time, immunized to wall clock changes.
// class PeriodicTimer {
// public:
//     PeriodicTimer(EventLoop* loop, double interval, const std::function<void()>& cb)
//         : loop_(loop),
//           timerfd_(muduo::net::detail::createTimerfd()),
//           timerfdChannel_(loop, timerfd_),
//           interval_(interval),
//           cb_(cb)
//     {
//         timerfdChannel_.setReadCallback(std::bind(&PeriodicTimer::handleRead, this));
//         timerfdChannel_.enableReading();
//     }

//     void start()
//     {
//         struct itimerspec spec;
//         memset(&spec, 0, sizeof(spec));
//         spec.it_interval = toTimeSpec(interval_);
//         spec.it_value = spec.it_interval;
//         int ret = timerfd_settime(timerfd_, 0 /* relative timer */, &spec, NULL);
//         if (ret)
//         {
//             LOG_SYSERR << "timerfd_settime()";
//         }
//     }

//     ~PeriodicTimer()
//     {
//         timerfdChannel_.disableAll();
//         timerfdChannel_.remove();
//         close(timerfd_);
//     }

// private:
//     void handleRead()
//     {
//         muduo::net::detail::readTimerfd(timerfd_, Timestamp::now());
//         if (cb_)
//             cb_();
//     }

//     static struct timespec toTimeSpec(double seconds)
//     {
//         struct timespec ts;
//         memset(&ts, 0, sizeof(ts));
//         const int64_t kNanoSecondsPerSecond = 1000000000;
//         const int kMinInterval = 100000;
//         int64_t nanoseconds = static_cast<int64_t>(seconds * kNanoSecondsPerSecond);
//         if (nanoseconds < kMinInterval)
//             nanoseconds = kMinInterval;
//         ts.tv_sec = static_cast<time_t>(nanoseconds / kNanoSecondsPerSecond);
//         ts.tv_nsec = static_cast<long>(nanoseconds % kNanoSecondsPerSecond);
//         return ts;
//     }

//     EventLoop* loop_;
//     const int timerfd_;
//     Channel timerfdChannel_;
//     const double interval_;  // in seconds
//     std::function<void()> cb_;
// };

// int main(int argc, char* argv[])
// {
//     LOG_INFO << "pid = " << getpid() << ", tid = " << this_thrd::tid()
//              << " Try adjusting the wall clock, see what happens.";
//     EventLoop loop;
//     PeriodicTimer timer(&loop, 1, std::bind(print, "PeriodicTimer"));
//     timer.start();
//     loop.queueInLoop(std::bind(print, "EventLoop::run"));
//     loop.loop();
//     sizeof(std::map<int, int>);
// }


























// #include "event_loop.hpp"

// class EchoServ {
// public:
//     EchoServ(kurisu::EventLoop* loop, int listenfd, sockaddr_u* addr) : m_loop(loop), m_poll(loop), m_channel(loop, listenfd), m_addr(addr)
//     {
//         m_channel.setReadCallback(std::bind(&EchoServ::Accept, this, m_stamp));
//         m_channel.enableReading();

//         m_loop->updateChannel(&m_channel);
//     }

// private:
//     void Accept(kurisu::Timestamp stamp)
//     {
//         m_fd = kurisu::socket_func::Accept(m_channel.fd(), &m_addr->sin);
//         m_channelVec.emplace_back(std::make_unique<kurisu::Channel>(m_loop, m_fd));
//         auto channel = m_channelVec.back().get();

//         channel->setReadCallback(std::bind(&EchoServ::ReadCallback, this, m_stamp));
//         channel->enableReading();

//         m_loop->updateChannel(m_channelVec.back().get());
//     }


//     void ReadCallback(kurisu::Timestamp stamp)
//     {
//         char buf[1024] = {0};
//         int fd = m_channelVec.back()->fd();
//         kurisu::socket_func::Read(fd, buf, 1024);
//         kurisu::socket_func::Write(fd, buf, 1024);
//     }

//     int m_fd = -1;
//     sockaddr_u* m_addr;
//     kurisu::EventLoop* m_loop;
//     kurisu::Timestamp m_stamp;
//     kurisu::Poller m_poll;
//     kurisu::Channel m_channel;
//     std::vector<std::unique_ptr<kurisu::Channel>> m_channelVec;
// };




// void Func(int listenfd, sockaddr_u* addr)
// {
//     kurisu::EventLoop loop;
//     EchoServ serv(&loop, listenfd, addr);
//     loop.loop();
// }

// int main()
// {
//     sockaddr_u addr;
//     int listenfd = kurisu::socket_func::MakeNonblockingSocket(AF_INET);
//     kurisu::socket_func::IpProtToAddr("0.0.0.0", 5005, &addr.sin);
//     kurisu::socket_func::BindAndListen(listenfd, &addr);
//     std::thread thrd1(Func, listenfd, &addr);
//     thrd1.join();

//     // int fd = kurisu::socket_func::Accept(listenfd, &addr.sin);
//     // char buf[1024] = {0};
//     // while (1)
//     // {
//     //     kurisu::socket_func::Read(fd, buf, 1024);
//     //     kurisu::socket_func::Write(fd, buf, 1024);
//     // }
// }





#include <memory>
#include <iostream>
#include "detail/socket.hpp"
#include "detail/acceptor.hpp"

class Entity {
public:
    void Print(){};
    void Print2(){};
};


int main()
{
    kurisu::SockAddr addr("0.0.0.0", 5005);
    kurisu::EventLoop loop;
    kurisu::Acceptor acceptor(&loop, addr, 5005);
    acceptor.SetConnectionCallback([](int fd, const kurisu::SockAddr addr) {
        LOG_INFO << "addr.ipPortString():" << addr.ipPortString() << "\n";
        auto a = kurisu::detail::GetPeerAddr(fd);
        LOG_INFO << "peer:" << a.ipPortString() << "\n";
    });
    acceptor.listen();
    loop.loop();
}