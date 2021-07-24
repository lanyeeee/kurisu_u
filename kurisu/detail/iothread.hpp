#pragma once
#include "../event_loop.hpp"

namespace kurisu {
    class EventLoopThread : uncopyable {
    public:
        EventLoopThread(const std::function<void(EventLoop*)>& cb, const std::string& name = std::string());
        ~EventLoopThread();
        EventLoop* startLoop();

    private:
        //io线程运行在这个函数里
        void threadFunc();

        EventLoop* loop_ = nullptr;
        bool exiting_ = false;
        Thread thread_;
        std::mutex mutex_;
        std::condition_variable cond_;
        std::function<void(EventLoop*)> callback_;  //初始化
    };

    inline EventLoopThread::EventLoopThread(const std::function<void(EventLoop*)>& cb, const std::string& name)
        : thread_(std::bind(&EventLoopThread::threadFunc, this), name), callback_(cb) {}
    inline EventLoopThread::~EventLoopThread()
    {
        exiting_ = true;
        if (loop_ != nullptr)  // not 100% race-free, eg. threadFunc could be running callback_.
        {
            // still a tiny chance to call destructed object, if threadFunc exits just now.
            // but when EventLoopThread destructs, usually programming is exiting anyway.
            loop_->quit();
            thread_.join();
        }
    }
    inline EventLoop* EventLoopThread::startLoop()
    {
        thread_.start();

        EventLoop* loop = nullptr;
        {
            std::unique_lock locker(mutex_);
            if (loop_ == nullptr)
                cond_.wait(locker, [this] { loop_ != nullptr; });
            loop = loop_;
        }

        return loop;
    }
    inline void EventLoopThread::threadFunc()
    {
        EventLoop loop;

        if (callback_)
            callback_(&loop);

        {
            std::lock_guard locker(mutex_);
            loop_ = &loop;
            cond_.notify_one();
        }

        loop.loop();
        std::lock_guard locker(mutex_);
        loop_ = nullptr;
        //这个函数结束，io线程就退出了
    }


}  // namespace kurisu