#include <vector>
#include <stdio.h>
#include <iostream>
#include <thread>
#include <memory>
#include <thread>
#include <muduo/base/noncopyable.h>
#include <muduo/base/Thread.h>
#include <muduo/base/CurrentThread.h>
#include <boost/ptr_container/ptr_vector.hpp>
#include "thrd.hpp"
#include <unistd.h>
#include <algorithm>
#include <pthread.h>
#include "blocking_queue.hpp"
#include <map>
#include <string>
#include <vector>
#include <stdio.h>
#include <unistd.h>
#include "time_stamp.hpp"
#include "blocking_circular_queue.hpp"

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

class Test {
public:
    Test(int numThreads)
        : queue_(20),
          latch_(numThreads)
    {
        threads_.reserve(numThreads);
        for (int i = 0; i < numThreads; ++i)
        {
            char name[32];
            snprintf(name, sizeof name, "work thread %d", i);
            threads_.emplace_back(new kurisu::Thread(
                std::bind(&Test::threadFunc, this), std::string(name)));
        }
        for (auto& thr : threads_)
        {
            thr->start();
        }
    }

    void run(int times)
    {
        printf("waiting for count down latch\n");
        latch_.wait();
        printf("all threads started\n");
        for (int i = 0; i < times; ++i)
        {
            char buf[32];
            snprintf(buf, sizeof buf, "hello %d", i);
            queue_.push(buf);
            printf("tid=%d, put data = %s, size = %zd\n", kurisu::this_thrd::tid(), buf, queue_.size());
        }
    }

    void joinAll()
    {
        for (size_t i = 0; i < threads_.size(); ++i)
        {
            queue_.push("stop");
        }

        for (auto& thr : threads_)
        {
            thr->join();
        }
    }

private:
    void threadFunc()
    {
        printf("tid=%d, %s started\n",
               kurisu::this_thrd::tid(),
               kurisu::this_thrd::name());

        latch_.CountDown();
        bool running = true;
        while (running)
        {
            std::string d(queue_.take());
            printf("tid=%d, get data = %s, size = %zd\n", kurisu::this_thrd::tid(), d.c_str(), queue_.size());
            running = (d != "stop");
        }

        printf("tid=%d, %s stopped\n",
               kurisu::this_thrd::tid(),
               kurisu::this_thrd::name());
    }

    kurisu::BlockingCircularQueue<std::string> queue_;
    kurisu::CountDownLatch latch_;
    std::vector<std::unique_ptr<kurisu::Thread>> threads_;
};

void testMove()
{
#if BOOST_VERSION >= 105500L
    kurisu::BlockingCircularQueue<std::unique_ptr<int>> queue(10);
    queue.push(std::unique_ptr<int>(new int(42)));
    std::unique_ptr<int> x = queue.take();
    printf("took %d\n", *x);
    *x = 123;
    queue.push(std::move(x));
    std::unique_ptr<int> y;
    y = queue.take();
    printf("took %d\n", *y);
#endif
}

int main()
{
    printf("pid=%d, tid=%d\n", ::getpid(), kurisu::this_thrd::tid());
    testMove();
    Test t(5);
    t.run(100);
    t.joinAll();

    printf("number of created threads %d\n", kurisu::Thread::numCreated());
}
