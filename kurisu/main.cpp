#include <vector>
#include <stdio.h>
#include <iostream>
#include <thread>
#include <memory>
#include <thread>
#include <muduo/base/noncopyable.h>
#include <muduo/base/Thread.h>
#include <muduo/base/CurrentThread.h>
#include "boost/ptr_container/ptr_vector.hpp"
#include "thrd.hpp"
#include <unistd.h>
#include <algorithm>
#include <pthread.h>
#include "blocking_queue.hpp"

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
    Test(int thrdNum) : latch(1), num(thrdNum)
    {
        for (int i = 0; i < num; i++)
            vec.push_back(new kurisu::Thread(std::bind(&Test::Func, this), std::to_string(i)));
        for (auto&& item : vec)
            item.start();
    }
    void Run() { latch.CountDown(); }
    void JoinAll() { std::for_each(vec.begin(), vec.end(), std::bind(&kurisu::Thread::join, std::placeholders::_1)); }

private:
    void Func()
    {
        latch.wait();
        printf("tid=%d, %s started\n", kurisu::this_thrd::tid(), kurisu::this_thrd::name());
        printf("tid=%d, %s stoped\n", kurisu::this_thrd::tid(), kurisu::this_thrd::name());
    }

    kurisu::CountDownLatch latch;
    int num;
    boost::ptr_vector<kurisu::Thread> vec;
};

kurisu::BlockingQueue<int> que;

void Fn()
{
    kurisu::this_thrd::SleepFor(1'000'000);
    que.push(1);
}

int main()
{
    Timer time;
    kurisu::Thread thrd(Fn);
    thrd.start();
    que.push(1);
    int i = que.take();
    std::cout << i << std::endl;
    que.pop();
    std::cout << "done\n";
    time.Print();
}