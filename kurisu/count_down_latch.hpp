#pragma once
#include <mutex>
#include <condition_variable>
#include "copyable.hpp"


namespace kurisu {
    //门闩
    class CountDownLatch : uncopyable {
    public:
        explicit CountDownLatch(int count) : m_count(count) {}

        void wait();
        void CountDown();
        int GetCount() const;

    private:
        mutable std::mutex m_mu;  //使const函数也能lock
        std::condition_variable m_cond;
        int m_count;
    };
    inline void CountDownLatch::wait()
    {
        std::unique_lock locker(m_mu);
        while (m_count > 0)
            m_cond.wait(locker, [this] { return m_count == 0; });
    }
    inline void CountDownLatch::CountDown()
    {
        std::lock_guard locker(m_mu);
        m_count--;
        if (m_count == 0)
            m_cond.notify_all();
    }
    inline int CountDownLatch::GetCount() const
    {
        std::lock_guard locker(m_mu);
        return m_count;
    }

}  // namespace kurisu