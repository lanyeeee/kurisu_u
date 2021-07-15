// #include <vector>
// #include <stdio.h>
// #include <iostream>
// #include <thread>
// #include <memory>
// #include <thread>
// #include <muduo/base/noncopyable.h>
// #include <muduo/base/Thread.h>
// #include <muduo/base/ThreadPool.h>
// #include <muduo/base/CurrentThread.h>
// #include <boost/ptr_container/ptr_vector.hpp>
// #include "thrd.hpp"
// #include <unistd.h>
// #include <algorithm>
// #include <pthread.h>
// #include <map>
// #include <string>
// #include <vector>
// #include <stdio.h>
// #include <unistd.h>
// #include "time_stamp.hpp"
// #include "thrd_pool.hpp"
// #include <muduo/base/Singleton.h>
// #include <muduo/base/Logging.h>
// #include <errno.h>
// #include <fmt/format.h>
// #include "fixed_buf.hpp"
// #include "log_stream.hpp"
// #include <limits>
// #include <boost/test/unit_test.hpp>

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

// class MyCout {
// public:
//     MyCout() { std::cout << "Cons\n"; }
//     ~MyCout() { std::cout << "Des\n"; }
//     void Print() { std::cout << x << std::endl; }
//     int x = 0;
// };

// class Entity {
// public:
//     Entity(int x) : x(x) { std::cout << "Cons\n"; }
//     ~Entity() { std::cout << "Des\n"; }
//     void Print() { std::cout << x << std::endl; }
//     int x = 0;
// };


// // int main()
// // {
// //     std::string str;
// //     char buf[33] = {0};
// //     kurisu::Timestamp t;
// //     Timer time;
// //     void* p;
// //     double d = 1;
// //     // for (int i = 0; i < 1000000; i++)
// //     // {
// //     //     //str = String((void*)&i);
// //     //     //str = fmt::format("{}", fmt::ptr(p));


// //     //     //convertHex(buf + 2, (uint64_t)&p);
// //     //     p = &i;
// //     // }
// //     auto len = fmt::format_to(buf, "{:0.10g}", 1.1) - buf;
// //     time.Print();
// //     std::cout << buf << std::endl;
// //     std::cout << p << std::endl;
// // }


#include <iostream>
#include "time_stamp.hpp"
#include "log_stream.hpp"


int main()
{
    kurisu::LogStream os;
    std::string_view view = "haha";
    std::string str = "haha";
    os << "haha" << view << str;
}
