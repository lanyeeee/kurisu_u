#include <vector>
#include <stdio.h>
#include <iostream>
#include <thread>
#include <memory>
#include <thread>
#include <muduo/base/noncopyable.h>
#include <muduo/base/Thread.h>
#include <muduo/base/ThreadPool.h>
#include <muduo/base/CurrentThread.h>
#include <boost/ptr_container/ptr_vector.hpp>
#include "thrd.hpp"
#include <unistd.h>
#include <algorithm>
#include <pthread.h>
#include <map>
#include <string>
#include <vector>
#include <stdio.h>
#include <unistd.h>
#include "time_stamp.hpp"
#include "thrd_pool.hpp"

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

std::atomic_int32_t g = 0;

void Func()
{
    if (g < 400'000)
    {
        g++;
        usleep(1);
    }
}


int main()
{
    Timer time;
    kurisu::ThreadPool pool;
    pool.SetMaxQueueSize(0);
    pool.SetThrdNum(10);
    for (int i = 0; g < 400'000; i++)
        pool.run(Func);
    pool.stop();
    printf("%d\n", g.load());
    time.Print();
    // boost::circular_buffer<int> buf;
    // std::cout << buf.full() << std::endl;
}
