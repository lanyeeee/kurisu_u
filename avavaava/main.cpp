// #include <vector>
// #include <stdio.h>
// #include <iostream>
// #include <thread>
// #include <memory>
// #include <thread>
// #include "exception.hpp"
// #include "time_stamp.hpp"

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

// class Base : public std::enable_shared_from_this<Base> {
// public:
//     Base() { std::cout << "Base cons\n"; }
//     template <class T>
//     auto ptr_cast()
//     {
//         return std::static_pointer_cast<T>(shared_from_this());
//     }
//     virtual void Print() = 0;
//     virtual ~Base() { std::cout << "Base des\n"; }
// };

// class Entity : public Base {
// public:
//     Entity() { std::cout << "Entity cons\n"; }
//     void Print() override { std::cout << "Entity\n"; }
//     void EntityFunc() { std::cout << x << "\n"; }
//     ~Entity() { std::cout << "Entity des\n"; }
//     int x = 1;
// };

// template <class To, class From>
// To Func(From f)
// {
//     return (To)f;
// }

// class Home : public Base {
// public:
//     Home() { std::cout << "Home cons\n"; }
//     void Print() override { std::cout << "Home\n"; }
//     void HomeFunc() { std::cout << x << "\n"; }
//     ~Home() { std::cout << "Home des\n"; }
//     int x = 100;
// };

// std::vector<std::shared_ptr<Base>> vec;

// void Fn()
// {
//     throw ava::Exception("haha");
// }

// void Func()
// {
//     Fn();
// }

// int main()
// {
//     try
//     {
//         Func();
//     }
//     catch (const ava::Exception& except)
//     {
//         std::cout << "reason: " << except.what() << std::endl;
//         std::cout << "stack trace:\n"
//                   << except.StackTrace();
//     }
//     catch (...)
//     {
//         std::cout << "unknown exception\n";
//     }
//     // vec.push_back(std::make_shared<Home>());

//     // Timer time;
//     // for (int i = 0; i < 10000000; i++)
//     //     auto res = vec[0]->ptr_cast<Home>();
//     // time.Print();
// }



#include <functional>
#include <vector>
#include <stdio.h>
#include "exception.hpp"

class Bar {
public:
    void test(std::vector<std::string> names = {})
    {
        printf("Stack:\n%s\n", ava::this_thrd::StackTrace().c_str());
        [] {
            printf("Stack inside lambda:\n%s\n", ava::this_thrd::StackTrace().c_str());
        }();
        std::function<void()> func([] { printf("Stack inside std::function:\n%s\n", ava::this_thrd::StackTrace().c_str()); });
        func();

        func = std::bind(&Bar::callback, this);
        func();

        throw ava::Exception("oops");
    }

private:
    void callback()
    {
        printf("Stack inside std::bind:\n%s\n", ava::this_thrd::StackTrace().c_str());
    }
};

void foo()
{
    Bar b;
    b.test();
}

int main()
{
    try
    {
        foo();
    }
    catch (const ava::Exception& ex)
    {
        printf("reason: %s\n", ex.what());
        printf("stack trace:\n%s\n", ex.StackTrace());
    }
}
