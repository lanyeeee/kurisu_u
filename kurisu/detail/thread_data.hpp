#pragma once
#include <functional>
#include <string>
#include <sys/prctl.h>
#include "count_down_latch.hpp"
#include "this_thrd.hpp"
#include "../exception.hpp"


namespace kurisu {
    namespace detail {
        class ThreadData {
        public:
            ThreadData(std::function<void()> func, const std::string& name, pid_t& tid, CountDownLatch& latch)
                : m_func(std::move(func)), m_name(name), m_tid(tid), m_latch(latch) {}

            void run();

        public:
            std::function<void()> m_func;
            std::string m_name;
            pid_t& m_tid;
            CountDownLatch& m_latch;
        };
        inline void ThreadData::run()
        {
            m_tid = this_thrd::tid();
            m_latch.CountDown();
            this_thrd::t_threadName = m_name.empty() ? "kurisuThread" : m_name.c_str();
            prctl(PR_SET_NAME, this_thrd::t_threadName);  //给线程命名
            try
            {
                m_func();
                this_thrd::t_threadName = "finished";
            }
            catch (const Exception& ex)
            {
                this_thrd::t_threadName = "crashed";
                fprintf(stderr, "exception caught in Thread %s\n", m_name.c_str());
                fprintf(stderr, "reason: %s\n", ex.what());
                fprintf(stderr, "stack trace: %s\n", ex.StackTrace());
                abort();
            }
            catch (const std::exception& ex)
            {
                this_thrd::t_threadName = "crashed";
                fprintf(stderr, "exception caught in Thread %s\n", m_name.c_str());
                fprintf(stderr, "reason: %s\n", ex.what());
                abort();
            }
            catch (...)
            {
                this_thrd::t_threadName = "crashed";
                fprintf(stderr, "unknown exception caught in Thread %s\n", m_name.c_str());
                throw;  // rethrow
            }
        }

        inline void ThrdEntrance(std::shared_ptr<ThreadData> thrdData) { thrdData->run(); }

    }  // namespace detail
}  // namespace kurisu