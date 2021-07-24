#pragma once
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <fmt/format.h>
#include <memory>
#include "copyable.hpp"
#include "../exception.hpp"
#include "count_down_latch.hpp"
#include "thread_data.hpp"

namespace kurisu {
    class Thread : uncopyable {
    public:
        explicit Thread(std::function<void()> func, const std::string& name = std::string())
            : m_func(std::move(func)), m_name(name) { SetDefaultName(); }
        ~Thread();

        void start();
        void join() { m_thrd.join(); }  // return pthread_join()

        bool started() const { return m_started; }
        // pthread_t pthreadId() const { return pthreadId_; }
        pid_t tid() const { return m_tid; }
        const std::string& name() const { return m_name; }

        static int numCreated() { return m_createdNum; }

    private:
        void SetDefaultName();

        bool m_started = 0;
        pthread_t m_pthreadID = 0;
        pid_t m_tid = 0;
        std::function<void()> m_func;
        std::string m_name;
        CountDownLatch m_latch = CountDownLatch(1);
        std::thread m_thrd;
        static std::atomic_int32_t m_createdNum;
    };
    inline std::atomic_int32_t Thread::m_createdNum = 0;
    inline Thread::~Thread()
    {
        if (m_started && m_thrd.joinable())
            m_thrd.detach();
    }
    inline void Thread::SetDefaultName()
    {
        ++m_createdNum;
        if (m_name.empty())
            m_name = fmt::format("Thread{}", m_createdNum);
    }
    inline void Thread::start()
    {
        using namespace detail;
        m_started = true;
        auto thrdData = std::make_shared<ThreadData>(std::move(m_func), m_name, m_tid, m_latch);
        m_thrd = std::thread(ThrdEntrance, thrdData);
        m_pthreadID = m_thrd.native_handle();
        m_latch.wait();
    }

}  // namespace kurisu
