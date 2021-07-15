#pragma once
#include <mutex>
#include <condition_variable>
#include "thrd.hpp"
#include <deque>
#include <vector>
#include <functional>
#include <memory>
#include <fmt/format.h>

namespace kurisu {
    class ThreadPool : uncopyable {
    public:
        using BindFunc = std::function<void()>;
        explicit ThreadPool(const std::string& name = "ThreadPool") : m_name(name) {}
        ~ThreadPool();

        //这个函数的调用必须在SetThrdNum前，用于设置等待队列的大小
        void SetMaxQueueSize(int maxSize) { m_maxSize = maxSize; }
        void SetThrdNum(int thrdNum);

        void SetThreadInitCallback(const BindFunc& callback) { m_thrdInitCallBack = callback; }

        void stop();
        void run(BindFunc func);
        void join();

        const std::string& name() const { return m_name; }
        uint64_t size() const;

    private:
        //线程不安全，这个函数必须在m_mu已被锁上时才能调用
        //当 m_maxSize == 0时恒为不满
        bool full() const;
        void RunInThread();
        BindFunc take();

    private:
        bool m_running = 0;  //退出的标志
        uint64_t m_maxSize = 0;
        std::string m_name;
        mutable std::mutex m_mu;
        std::condition_variable m_notEmptyCond;
        std::condition_variable m_notFullCond;
        BindFunc m_thrdInitCallBack;
        std::vector<std::unique_ptr<Thread>> m_thrds;
        std::deque<BindFunc> m_task;
    };

    inline ThreadPool::~ThreadPool()
    {
        if (m_running)
            stop();
    }

    inline void ThreadPool::SetThrdNum(int thrdNum)
    {
        m_running = 1;
        m_thrds.reserve(thrdNum);
        for (int i = 0; i < thrdNum; i++)
        {
            std::string id = fmt::format("{}", i + 1);
            m_thrds.emplace_back(new Thread(std::bind(&kurisu::ThreadPool::RunInThread, this), m_name + id));  //创建线程
            m_thrds[i]->start();
        }

        if (thrdNum == 0 && m_thrdInitCallBack)  //如果创建的线程为0，也执行初始化后的回调函数
            m_thrdInitCallBack();
    }

    inline void ThreadPool::RunInThread()
    {
        try
        {
            if (m_thrdInitCallBack)
                m_thrdInitCallBack();  //如果有初始化的回调函数就执行
            while (m_running)
                if (BindFunc func(take()); func)  //从函数队列中拿出函数，是可执行的函数就执行，直到m_running被变成false
                    func();
        }
        catch (const Exception& ex)
        {
            fprintf(stderr, "exception caught in ThreadPool %s\n", m_name.data());
            fprintf(stderr, "reason: %s\n", ex.what());
            fprintf(stderr, "stack trace: %s\n", ex.StackTrace());
            abort();
        }
        catch (const std::exception& ex)
        {
            fprintf(stderr, "exception caught in ThreadPool %s\n", m_name.data());
            fprintf(stderr, "reason: %s\n", ex.what());
            abort();
        }
        catch (...)
        {
            fprintf(stderr, "unknown exception caught in ThreadPool %s\n", m_name.data());
            throw;  // rethrow
        }
    }

    inline ThreadPool::BindFunc ThreadPool::take()
    {
        std::unique_lock locker(m_mu);
        if (m_task.empty() && m_running)
            m_notEmptyCond.wait(locker, [this] { return !m_task.empty() || !m_running; });  //等到有任务为止

        BindFunc func;
        if (!m_task.empty())
        {
            func = std::move(m_task.front());  //取出函数
            m_task.pop_front();
        }
        if (m_maxSize > 0)
            m_notFullCond.notify_one();  //如果对等待队列做了大小限制，就通知其他线程，等待队列有空闲了

        return func;
    }

    inline void ThreadPool::run(BindFunc task)
    {
        if (m_thrds.empty())
            task();  //如果没有线程池，就直接用现在的线程执行函数
        else
        {
            std::unique_lock locker(m_mu);

            //如果 m_maxSize == 0，full()的返回值恒为false
            //此时会直接跳到后面将task加入队列，即不对等待队列的大小做限制
            //这样做效率可能会有所提高，但是会更占用更多内存
            //而且使用不当还会造成等待队列爆满的情况，建议还是设置一个大小
            //除非你很清楚你在干什么
            if (full() && m_running)
                m_notFullCond.wait(locker, [this] { return !full() || !m_running; });  //线程池中的线程都忙，就等到有空闲的线程为止

            if (!m_running)  //如果已经析构，线程退出
                return;

            m_task.emplace_back(std::move(task));  //将task加入队列
            //printf("m_task.size()=%lu\n", m_task.size());
            m_notEmptyCond.notify_one();  //通知其他线程等待队列已有任务
        }
    }

    inline void ThreadPool::stop()
    {
        {
            std::lock_guard locker(m_mu);
            m_running = 0;
            m_notFullCond.notify_all();
            m_notEmptyCond.notify_all();
        }
        for (auto&& thrd : m_thrds)
            thrd->join();
    }

    inline void ThreadPool::join()
    {
        CountDownLatch latch(1);

        //往线程池里加入一个倒计时任务
        run(std::bind(&kurisu::CountDownLatch::CountDown, &latch));

        //等待倒计时任务被执行
        //被执行了就说明在这个任务之前的任务都被执行了
        latch.wait();
        stop();
    }

    inline uint64_t ThreadPool::size() const
    {
        std::lock_guard locker(m_mu);
        return m_task.size();
    }

    inline bool ThreadPool::full() const { return m_maxSize > 0 && m_task.size() >= m_maxSize; }


}  // namespace kurisu