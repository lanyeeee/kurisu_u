#pragma once
#include <boost/circular_buffer.hpp>
#include <mutex>
#include <condition_variable>

namespace kurisu {
    template <class T>
    class BlockingCircularQueue {
    public:
        explicit BlockingCircularQueue(int maxSize) : m_circle(maxSize) {}
        void push(const T& t);
        void push(T&& t);
        T take();
        void pop();

        bool empty() const;
        bool full() const;
        uint64_t size() const;
        uint64_t capacity() const;

    private:
        mutable std::mutex m_mu;
        std::condition_variable m_notEmptyCond;
        std::condition_variable m_notFullCond;
        boost::circular_buffer<T> m_circle;
    };

    template <class T>
    inline void BlockingCircularQueue<T>::push(const T& t)
    {
        std::unique_lock locker(m_mu);
        if (m_circle.full())
            m_notFullCond.wait(locker, [this] { return !m_circle.full(); });
        m_circle.push_back(t);
        m_notEmptyCond.notify_one();
    }

    template <class T>
    inline void BlockingCircularQueue<T>::push(T&& t)
    {
        std::unique_lock locker(m_mu);
        if (m_circle.full())
            m_notFullCond.wait(locker, [this] { return !m_circle.full(); });
        m_circle.push_back(std::move(t));
        m_notEmptyCond.notify_one();
    }

    template <class T>
    inline T BlockingCircularQueue<T>::take()
    {
        std::unique_lock locker(m_mu);
        if (m_circle.empty())
            m_notEmptyCond.wait(locker, [this] { return !m_circle.empty(); });
        T t = std::move(m_circle.front());
        m_circle.pop_front();
        m_notFullCond.notify_one();
        return t;
    }

    template <class T>
    inline void BlockingCircularQueue<T>::pop()
    {
        std::unique_lock locker(m_mu);
        if (m_circle.empty())
            m_notEmptyCond.wait(locker, [this] { return !m_circle.empty(); });
        m_circle.pop_front();
        m_notFullCond.notify_one();
    }


    template <class T>
    inline bool BlockingCircularQueue<T>::empty() const
    {
        std::lock_guard locker(m_mu);
        return m_circle.empty();
    }

    template <class T>
    inline bool BlockingCircularQueue<T>::full() const
    {
        std::lock_guard locker(m_mu);
        return m_circle.full();
    }

    template <class T>
    inline uint64_t BlockingCircularQueue<T>::size() const
    {
        std::lock_guard locker(m_mu);
        return m_circle.size();
    }

    template <class T>
    inline uint64_t BlockingCircularQueue<T>::capacity() const
    {
        std::lock_guard locker(m_mu);
        return m_circle.capacity();
    }
}  // namespace kurisu