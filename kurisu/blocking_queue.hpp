#pragma once
#include <deque>
#include <mutex>
#include "copyable.hpp"
#include <condition_variable>

namespace kurisu {
    template <class T>
    class BlockingQueue : nocopyable {
    public:
        BlockingQueue() {}
        void push(const T& t);
        void push(T&& t);
        void pop();
        T take();
        uint64_t size() const
        {
            std::lock_guard locker(m_mu);
            return m_deque.size();
        }

    private:
        mutable std::mutex m_mu;
        std::condition_variable m_cond;
        std::deque<T> m_deque;
    };



    template <class T>
    inline void BlockingQueue<T>::push(const T& t)
    {
        std::lock_guard locker(m_mu);
        m_deque.emplace_back(t);
        m_cond.notify_one();
    }

    template <class T>
    inline void BlockingQueue<T>::push(T&& t)
    {
        {
            std::lock_guard locker(m_mu);
            m_deque.emplace_back(std::move(t));
        }
        m_cond.notify_one();
    }

    template <class T>
    inline T BlockingQueue<T>::take()
    {
        std::unique_lock locker(m_mu);
        if (m_deque.empty())
            m_cond.wait(locker, [this] { return !m_deque.empty(); });
        T front = std::move(m_deque.front());
        m_deque.pop_front();
        return front;
    }

    template <class T>
    inline void BlockingQueue<T>::pop()
    {
        std::unique_lock locker(m_mu);
        if (m_deque.empty())
            m_cond.wait(locker, [this] { return !m_deque.empty(); });
        m_deque.pop_front();
    }
}  // namespace kurisu