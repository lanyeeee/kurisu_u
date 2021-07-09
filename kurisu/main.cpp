#include <vector>
#include <stdio.h>
#include <iostream>
#include <thread>
#include <memory>
#include <thread>
#include <muduo/base/noncopyable.h>
#include <muduo/base/Thread.h>
#include <muduo/base/CurrentThread.h>
#include "thrd.hpp"

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

int Func(int x) { return x; }
int main()
{
    Timer time;

    for (int i = 0; i < 10000; i++)
    {
        auto res = muduo::Thread(std::bind(Func, 1));
        res.start();
    }

    // for (auto&& item : vec)
    //     item.join();
    time.Print();
}