#pragma once
#include <memory>
#include <mutex>
#include <string>
#include <string.h>
#include <string_view>
#include "copyable.hpp"
#include "logger.hpp"
#include "../time_stamp.hpp"
#include "process_info.hpp"
#include "string_arg.hpp"

namespace kurisu {

    namespace detail {
        class LogFileAppender : uncopyable {
        public:
            explicit LogFileAppender(StringArg filename)
                : m_fp(fopen(filename.c_str(), "ae")) { setbuffer(m_fp, m_buf, sizeof(m_buf)); }
            ~LogFileAppender() { fclose(m_fp); }
            void append(const char* logline, const uint64_t len);
            void flush() { fflush(m_fp); }
            uint64_t WrittenBytes() const { return m_writtenBytes; }
            uint64_t write(const char* logline, const uint64_t len) { return fwrite_unlocked(logline, 1, len, m_fp); }


        private:
            FILE* m_fp;
            char m_buf[64 * 1024];  //正常情况下日志先写进这里,满了或者flush才往内核缓冲区写,减少系统调用
            uint64_t m_writtenBytes = 0;
        };

        inline void LogFileAppender::append(const char* logline, const uint64_t len)
        {
            uint64_t written = 0;
            while (written != len)
            {
                uint64_t remain = len - written;
                uint64_t n = write(logline + written, remain);
                if (n != remain)
                {
                    int err = ferror(m_fp);
                    if (err)
                    {
                        fprintf(stderr, "AppendFile::append() failed %s\n", strerror_tl(err));
                        break;
                    }
                }
                written += n;
            }
            m_writtenBytes += written;
        }

    }  // namespace detail



    class SyncLogFile : uncopyable {
    public:
        SyncLogFile(const std::string& filename, uint64_t rollSize, bool isLocalTimeZone, bool threadSafe = true, int flushInterval = 3, int checkEveryN = 1024)
            : m_filename(filename), k_RollSize(rollSize), k_FlushInterval(flushInterval), k_CheckEveryN(checkEveryN), m_isLocalTimeZone(isLocalTimeZone), m_mu(threadSafe ? new std::mutex : NULL) { roll(); }
        ~SyncLogFile() = default;
        void append(const char* logline, const uint64_t len);
        void flush();
        bool roll();

    private:
        void append_unlocked(const char* logline, const uint64_t len);
        std::string MakeLogFileName(const std::string& basename, const Timestamp& now);

        const std::string m_filename;
        const uint64_t k_RollSize;  //   多少byte就roll一次
        const int k_FlushInterval;  //多少秒就flush一次
        const int k_CheckEveryN;    //每写入N次就强制检查一次，与m_count配合使用

        bool m_isLocalTimeZone;  //是否使用本地时区
        int m_count = 0;         //记录被写入的次数，与k_CheckEveryN配合使用
        time_t m_day;            //第几天
        time_t m_lastRoll = 0;   //上次roll的时间
        time_t m_lastFlush = 0;  //上次flush的时间
        std::unique_ptr<std::mutex> m_mu;
        std::unique_ptr<detail::LogFileAppender> m_appender;
        static const int k_OneDaySeconds = 60 * 60 * 24;  //一天有多少秒
    };

    inline void SyncLogFile::append(const char* logline, uint64_t len)
    {
        if (m_mu)
        {
            std::lock_guard locker(*m_mu);
            append_unlocked(logline, len);
        }
        else
            append_unlocked(logline, len);
    }
    inline void SyncLogFile::flush()
    {
        if (m_mu)
        {
            std::lock_guard locker(*m_mu);
            m_appender->flush();
        }
        else
            m_appender->flush();
    }
    inline bool SyncLogFile::roll()
    {
        auto timestamp = Timestamp();
        time_t now = timestamp.as_time_t();

        //每过0点day+1
        time_t day = now / k_OneDaySeconds * k_OneDaySeconds;

        if (now > m_lastRoll)
        {
            std::string filename = MakeLogFileName(m_filename, timestamp);
            m_lastRoll = now;
            m_lastFlush = now;
            m_day = day;
            m_appender.reset(new detail::LogFileAppender(filename));
            return true;
        }
        return false;
    }
    inline std::string SyncLogFile::MakeLogFileName(const std::string& basename, const Timestamp& timestamp)
    {
        std::string filename;
        filename.reserve(basename.size() + 64);
        filename = basename;

        filename += '.';
        if (!m_isLocalTimeZone)
            filename += timestamp.GmFormatString();
        else
            filename += timestamp.LocalFormatString();

        filename += '.';
        filename += process::HostName();

        filename += fmt::format(".{}", process::pid());

        filename += ".log";
        return filename;
    }
    inline void SyncLogFile::append_unlocked(const char* logline, const uint64_t len)
    {
        m_appender->append(logline, len);

        if (m_appender->WrittenBytes() > (uint64_t)k_RollSize)  //如果写入的大小>rollSize就roll
            roll();
        else if (++m_count >= k_CheckEveryN)
        {
            m_count = 0;  //如果写入次数>=这个数就重新计数
            time_t now = time(0);
            time_t day = now / k_OneDaySeconds * k_OneDaySeconds;
            if (day != m_day)  //如果过了0点就roll
                roll();
            else if (now - m_lastFlush > (time_t)k_FlushInterval)  //没过0点就flush
            {
                m_lastFlush = now;
                m_appender->flush();
            }
        }
    }






    class AsyncLogFile : uncopyable {
    public:
        AsyncLogFile(const std::string& basename, int64_t rollSize, bool isLocalTimeZone = false, int flushInterval = 3);
        ~AsyncLogFile();

        void append(const char* logline, uint64_t len);
        void stop();

    private:
        using Buf = detail::FixedBuffer<detail::k_LargeBuf>;
        using BufVector = std::vector<std::unique_ptr<Buf>>;
        using BufPtr = BufVector::value_type;
        //m_thrd在此函数内循环
        void Loop();

    private:
        const int k_flushInterval;           //多少秒就flush一次
        bool m_isLocalTimeZone;              //是否使用本地时区
        std::atomic_bool m_running = false;  //是否已运行
        const std::string m_fileName;
        const int64_t m_rollSize;  //  多少byte就roll一次
        Thread m_thrd;
        CountDownLatch m_latch = CountDownLatch(1);
        std::mutex m_mu;
        std::condition_variable m_fullCond;  //前端的buf是否已满
        BufPtr m_thisBuf;                    //前端用的buf
        BufPtr m_nextBuf;                    //前端的备用buf
        BufVector m_bufs;                    //后端用的buf
    };

    inline AsyncLogFile::AsyncLogFile(const std::string& basename, int64_t rollSize, bool localTimeZone, int flushInterval)
        : k_flushInterval(flushInterval),
          m_isLocalTimeZone(localTimeZone),
          m_fileName(basename),
          m_rollSize(rollSize),
          m_thrd(std::bind(&AsyncLogFile::Loop, this), "Async Logger"),
          m_thisBuf(new Buf),
          m_nextBuf(new Buf)
    {
        m_thisBuf->zero();
        m_nextBuf->zero();
        m_bufs.reserve(16);
        Logger::SetTimeZone(m_isLocalTimeZone);

        m_running = true;
        m_thrd.start();
        m_latch.wait();
    }
    inline AsyncLogFile::~AsyncLogFile()
    {
        if (m_running)
            stop();
    }
    inline void AsyncLogFile::append(const char* logline, uint64_t len)
    {
        std::lock_guard locker(m_mu);
        if (m_thisBuf->AvalibleSize() > len)  //没满
            m_thisBuf->append(logline, len);
        else  //满了
        {
            m_bufs.push_back(std::move(m_thisBuf));  //将此buf加入待输出的队列

            if (m_nextBuf)
                m_thisBuf = std::move(m_nextBuf);  //拿下一个空的buf
            else
                m_thisBuf.reset(new Buf);  // 没有空buf了就创建一个新的，但几乎不会发生

            m_thisBuf->append(logline, len);
            m_fullCond.notify_one();  //通知其他线程，buf满了
        }
    }
    inline void AsyncLogFile::stop()
    {
        m_running = false;
        m_fullCond.notify_one();
        m_thrd.join();
    }
    inline void AsyncLogFile::Loop()
    {
        m_latch.CountDown();
        SyncLogFile logFile(m_fileName, m_rollSize, m_isLocalTimeZone, false);

        //准备两个空的Buf
        BufPtr newBuf1(new Buf);
        BufPtr newBuf2(new Buf);
        newBuf1->zero();
        newBuf2->zero();

        BufVector bufVec;  //空Buf
        bufVec.reserve(16);
        while (m_running)
        {
            {
                std::unique_lock locker(m_mu);
                //经常发生的情况
                if (m_bufs.empty())
                    m_fullCond.wait_for(locker, std::chrono::seconds(k_flushInterval));  //等满的信号，最多等m_flushInterval秒

                m_bufs.push_back(std::move(m_thisBuf));  //将当前buf加入待输出的队列
                m_thisBuf = std::move(newBuf1);          //当前buf换成一个空的buf


                //把前端的bufVec与后端的bufVec交换，
                // 前端换上空的继续接收日志，后端来处理前端接收到的日志
                bufVec.swap(m_bufs);
                if (!m_nextBuf)                      //如果nextBuf被用了
                    m_nextBuf = std::move(newBuf2);  //就补上
            }

            if (bufVec.size() > 25)  //生产效率大于消费效率
            {
                char buf[256];
                fmt::format_to(buf, "Dropped log messages at {}, {} larger buffers\n",
                               Timestamp::now().GmFormatString(), bufVec.size() - 2);
                fputs(buf, stderr);
                logFile.append(buf, strlen(buf));
                bufVec.erase(bufVec.begin() + 2, bufVec.end());  //处理方法是将buf都舍弃掉，只留下两个，废物利用
            }
            for (auto&& item : bufVec)  //遍历，输出所有要输出的buf
                logFile.append(item->data(), item->size());

            if (bufVec.size() > 2)
                bufVec.resize(2);  // 丢掉所有的buf，留两个是为了给之后newBuf1和newBuf2用，属于废物利用

            if (!newBuf1)  //如果newBuf1被用了就补上
            {
                newBuf1 = std::move(bufVec.back());
                bufVec.pop_back();
                newBuf1->reset();
            }

            if (!newBuf2)  //如果newBuf2被用了也补上
            {
                newBuf2 = std::move(bufVec.back());
                bufVec.pop_back();
                newBuf2->reset();
            }

            bufVec.clear();
            logFile.flush();
        }
        logFile.flush();
    }


}  // namespace kurisu