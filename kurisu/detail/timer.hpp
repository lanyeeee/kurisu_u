#pragma once
#include <atomic>
#include <memory>
#include "copyable.hpp"
#include "../time_stamp.hpp"

namespace kurisu {
    class Timer : uncopyable {
    public:
        Timer(std::function<void()> cb, Timestamp when, double interval)
            : m_runtime(when), m_interval(interval), m_repeat(interval > 0.0), m_callback(std::move(cb)) {}

        void run() const { m_callback(); }
        void restart();

        Timestamp GetRuntime() const { return m_runtime; }
        bool IsRepeat() const { return m_repeat; }



    private:
        Timestamp m_runtime;                     //超时的时刻(理想状态下回调函数运行的时刻)
        const double m_interval;                 //触发超时的间隔,为0则代表是一次性定时器
        const bool m_repeat;                     //是否重复
        const std::function<void()> m_callback;  //定时器回调函数
    };

    inline void Timer::restart()
    {
        //如果是重复的定时器
        if (m_repeat)
            m_runtime = AddTime(m_runtime, m_interval);  //重新计算下一个超时时刻
        else
            m_runtime = Timestamp::invalid();
    }



    class TimerID {
    public:
        explicit TimerID(Timer* timer) : m_timer(timer) {}

    private:
        std::pair<Timestamp, Timer*> Key() { return std::make_pair(m_timer->GetRuntime(), m_timer); }
        Timer* m_timer;
        friend class TimerQueue;
    };
}  // namespace kurisu