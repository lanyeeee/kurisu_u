#pragma once
#include <string>
#include <string.h>
#include <string_view>
#include <chrono>
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <deque>
#include <map>
#include <set>
#include <any>


uint64_t htonll(uint64_t val);
uint64_t ntohll(uint64_t val);

namespace kurisu {
    namespace detail {
        class copyable {
        protected:
            copyable() = default;
            ~copyable() = default;
        };

        class uncopyable {
        protected:
            uncopyable(){};
            ~uncopyable(){};

        private:
            uncopyable(const uncopyable& that);
            uncopyable& operator=(const uncopyable& that);
        };
    }  // namespace detail

    class Timestamp : detail::copyable {
    public:
        Timestamp() : m_stamp(std::chrono::system_clock::now()) {}
        explicit Timestamp(std::chrono::system_clock::time_point stamp) : m_stamp(stamp) {}

        auto GetStamp() const { return m_stamp; }
        void Swap(Timestamp& other) { std::swap(m_stamp, other.m_stamp); }
        bool Valid() { return m_stamp != s_invalid; }
        char* GmLogFormat(char* buf) const;
        char* LocalLogFormat(char* buf) const;
        // format gmtime
        std::string GmFormatString() const;
        std::string LocalFormatString() const;
        int64_t Msec() const;
        int64_t Usec() const;
        int64_t Nsec() const;
        int64_t Sec() const;
        time_t As_time_t() { return (time_t)Sec(); }

        bool operator<(const Timestamp& other) const { return this->GetStamp() < other.GetStamp(); }
        bool operator<=(const Timestamp& other) const { return this->GetStamp() <= other.GetStamp(); }
        bool operator>(const Timestamp& other) const { return this->GetStamp() > other.GetStamp(); }
        bool operator>=(const Timestamp& other) const { return this->GetStamp() >= other.GetStamp(); }
        bool operator!=(const Timestamp& other) const { return this->GetStamp() != other.GetStamp(); }
        bool operator==(const Timestamp& other) const { return this->GetStamp() == other.GetStamp(); }

        static Timestamp Now() { return Timestamp(); }
        static Timestamp Invalid() { return Timestamp(s_invalid); }
        // seconds
        static double TimeDifference(Timestamp high, Timestamp low);
        static Timestamp AddTime(Timestamp stamp, double second);

    private:
        static const std::chrono::system_clock::time_point s_invalid;
        std::chrono::system_clock::time_point m_stamp;
    };

    namespace this_thrd {
        namespace detail {
            pid_t GetTid();
            std::string Demangle(const char* symbol);
        }  // namespace detail

        void CacheTid();
        int Tid();
        const char* TidString();
        int TidStringLength();
        const char* Name();

        bool IsMainThread();
        void SleepFor(int us);
        std::string StackTrace();

    }  // namespace this_thrd

    class Exception : public std::exception {
    public:
        Exception(std::string msg) : m_msg(std::move(msg)), m_stack(kurisu::this_thrd::StackTrace()) {}
        ~Exception() noexcept override = default;

        const char* what() const noexcept override { return m_msg.data(); }
        const char* StackTrace() const noexcept { return m_stack.data(); }

    private:
        std::string m_msg;
        std::string m_stack;
    };

    namespace detail {
        class StringArg : copyable {
        public:
            StringArg(const char* str) : m_str(str) {}
            StringArg(const std::string& str) : m_str(str.c_str()) {}
            StringArg(const std::string_view& str) : m_str(str.data()) {}
            const char* c_str() const { return m_str; }

        private:
            const char* m_str;
        };

        class KnownLengthString : copyable {
        public:
            KnownLengthString(const char* str, uint64_t len) : m_buf(str), m_size(len) {}
            KnownLengthString& operator=(const KnownLengthString& other)
            {
                m_buf = other.m_buf;
                m_size = other.m_size;
                return *this;
            }
            const char* m_buf;
            uint64_t m_size;
        };

        class FixedString : copyable {
        public:
            FixedString(const char* str, uint64_t len) : m_buf(str), m_size(len) {}
            FixedString& operator=(const FixedString& other)
            {
                m_buf = other.m_buf;
                m_size = other.m_size;
                return *this;
            }
            const char* m_buf;
            uint64_t m_size;
        };

        class CountDownLatch : uncopyable {
        public:
            explicit CountDownLatch(int count) : m_count(count) {}

            void Wait();
            void CountDown();
            int GetCount() const;

        private:
            mutable std::mutex m_mu;  // 使const函数也能lock
            std::condition_variable m_cond;
            int m_count;
        };

        class ThreadData : uncopyable {
        public:
            ThreadData(std::function<void()> func, const std::string& name, pid_t& tid, CountDownLatch& latch)
                : m_func(std::move(func)), m_name(name), m_tid(tid), m_latch(latch) {}

            void Run();

        public:
            std::function<void()> m_func;
            std::string m_name;
            pid_t& m_tid;
            CountDownLatch& m_latch;
        };

        void ThrdEntrance(std::shared_ptr<ThreadData> thrdData);

        constexpr uint64_t k_SmallBuf = 4'000;
        constexpr uint64_t k_LargeBuf = 4'000'000;

        template <uint64_t SIZE>
        class FixedBuffer : uncopyable {
        public:
            FixedBuffer() : m_index(m_data) { m_data[SIZE] = '\0'; }

            uint64_t Size() const { return (uint64_t)(m_index - m_data); }
            const char* Data() const { return m_data; }
            void IndexShiftRight(uint64_t num) { m_index += num; }
            char* Index() { return m_index; }
            void Reset() { m_index = m_data; }
            void Zero() { bzero(m_data, SIZE); }
            std::string String() const { return std::string(m_data, Size()); }
            std::string_view StringView() const { return std::string_view(m_data, Size()); }
            uint64_t AvalibleSize() { return (uint64_t)(End() - m_index); }

            void Append(const char* buf, uint64_t len)
            {
                auto n = AvalibleSize();
                if (n > len)
                {
                    memcpy(m_index, buf, len);
                    m_index += len;
                }
                else
                {
                    memcpy(m_index, buf, n);
                    m_index += n;
                }
            }

            const char* c_str() const
            {
                *m_index = '\0';
                return m_data;
            }


        private:
            const char* End() const { return m_data + SIZE; }


        private:
            char m_data[SIZE + 1];
            char* m_index;
        };


        // 效率很高的itoa算法，比to_string快5倍以上
        template <typename T>
        uint64_t Convert(char buf[], T value)
        {
            static const char digits[] = "9876543210123456789";
            static const char* zero = digits + 9;
            T i = value;
            char* p = buf;

            do
            {
                int lsd = (int)(i % 10);
                i /= 10;
                *p++ = zero[lsd];
            } while (i != 0);

            if (value < 0)
                *p++ = '-';

            *p = '\0';
            std::reverse(buf, p);

            return p - buf;
        }
        // 效率很高的pointer->str算法
        uint64_t ConvertHex(char buf[], uintptr_t value);

        // 用于读小于64KB的文件
        class ReadSmallFile : uncopyable {
        public:
            ReadSmallFile(StringArg filepath);
            ~ReadSmallFile();
            // 把文件的数据读到传进来的std::string里 返回errno
            int ReadToString(int maxSize, std::string& content, int64_t* fileSize, int64_t* modifyTime, int64_t* createTime);
            // 把文件的数据读到m_buf里  返回errno
            int ReadToBuffer(int* size);
            const char* Buffer() const { return m_buf; }

            static const int k_BufferSize = 64 * 1024;  // byte

        private:
            int m_fd;
            int m_err;
            char m_buf[k_BufferSize];
        };

        // 将filepath对应的文件读到传进来的std::string里
        int ReadFile(StringArg filepath, int maxSize, std::string& content, int64_t* fileSize = nullptr, int64_t* modifyTime = nullptr, int64_t* createTime = nullptr);
        int FdDirFilter(const struct dirent* d);

        int TaskDirFilter(const struct dirent* d);

        int ScanDir(const char* dirpath, int (*filter)(const struct dirent*));

        // 生成errno的str
        const char* strerror_tl(int savedErrno);

        class LogFileAppender : uncopyable {
        public:
            explicit LogFileAppender(StringArg filename)
                : m_fp(fopen(filename.c_str(), "ae")) { setbuffer(m_fp, m_buf, sizeof(m_buf)); }
            ~LogFileAppender() { fclose(m_fp); }
            void Append(const char* logline, const uint64_t len);
            void Flush() { fflush(m_fp); }
            uint64_t WrittenBytes() const { return m_writtenBytes; }
            uint64_t Write(const char* logline, const uint64_t len) { return fwrite_unlocked(logline, 1, len, m_fp); }


        private:
            FILE* m_fp;
            char m_buf[64 * 1024];  // 正常情况下日志先写进这里,满了或者flush才往内核缓冲区写,减少系统调用
            uint64_t m_writtenBytes = 0;
        };


        class Thread : uncopyable {
        public:
            explicit Thread(std::function<void()> func, const std::string& name = std::string())
                : m_func(std::move(func)), m_name(name) { SetDefaultName(); }
            ~Thread();

            void Start();
            void Join() { m_thrd.join(); }

            bool Started() const { return m_isStarted; }
            pid_t Tid() const { return m_tid; }
            const std::string& Name() const { return m_name; }

            static int NumCreated() { return s_createdNum; }

        private:
            void SetDefaultName();

            bool m_isStarted = 0;
            pthread_t m_pthreadID = 0;
            pid_t m_tid = 0;
            std::function<void()> m_func;
            std::string m_name;
            detail::CountDownLatch m_latch = detail::CountDownLatch(1);
            std::thread m_thrd;
            static std::atomic_int32_t s_createdNum;
        };


        class ThreadPool : uncopyable {
        public:
            explicit ThreadPool(const std::string& name = "ThreadPool") : m_name(name) {}
            ~ThreadPool();
            // 这个函数的调用必须在SetThrdNum前，用于设置等待队列的大小
            void SetMaxQueueSize(int maxSize) { m_maxSize = maxSize; }
            // 设置线程池的大小
            void SetThrdNum(int thrdNum);
            // 设置创建线程池时会调用的初始化函数
            void SetThreadInitCallback(const std::function<void()>& callback) { m_thrdInitCallBack = callback; }

            void Stop();
            // 在线程池内执行该函数
            void Run(std::function<void()> func);
            void Join();

            const std::string& Name() const { return m_name; }
            uint64_t Size() const;

        private:
            // 线程不安全，这个函数必须在m_mu已被锁上时才能调用
            // 当 m_maxSize == 0时恒为不满
            bool Full() const;
            // 线程池在这个函数中循环
            void Handle();
            std::function<void()> Take();

        private:
            std::atomic_bool m_isRunning = 0;  // 退出的标志
            uint64_t m_maxSize = 0;
            std::string m_name;
            mutable std::mutex m_mu;
            std::condition_variable m_notEmptyCond;
            std::condition_variable m_notFullCond;
            std::function<void()> m_thrdInitCallBack;
            std::vector<std::unique_ptr<Thread>> m_thrds;
            std::deque<std::function<void()>> m_tasks;
        };



        class LogStream : uncopyable {
        public:
            using FixedBuf = FixedBuffer<k_SmallBuf>;

            void Append(const char* data, int len) { m_buf.Append(data, len); }
            const FixedBuf& Buffer() const { return m_buf; }
            void ResetBuffer() { m_buf.Reset(); }

            LogStream& operator<<(bool val);
            LogStream& operator<<(char val);
            LogStream& operator<<(int16_t val);
            LogStream& operator<<(uint16_t val);
            LogStream& operator<<(int val);
            LogStream& operator<<(uint32_t val);
            LogStream& operator<<(int64_t val);
            LogStream& operator<<(uint64_t val);
            LogStream& operator<<(float val);
            LogStream& operator<<(double val);
            LogStream& operator<<(const void* p);
            LogStream& operator<<(const char* p);
            LogStream& operator<<(const unsigned char* p);
            LogStream& operator<<(const std::string& str);
            LogStream& operator<<(const std::string_view& str);
            LogStream& operator<<(const FixedBuf& buf);
            LogStream& operator<<(const FixedString& str);
            LogStream& operator<<(const detail::KnownLengthString& str);

        private:
            template <class T>
            void FormatInt(T val);

        private:
            FixedBuf m_buf;
            static const int k_MaxSize = 32;  // 除const char* std::strubg std::string_view之外，一次能写入的最大字节数
        };

        template <class T>
        void LogStream::FormatInt(T val)
        {
            if (m_buf.AvalibleSize() >= k_MaxSize)
            {
                uint64_t len = Convert(m_buf.Index(), val);
                m_buf.IndexShiftRight(len);
            }
        }



    }  // namespace detail

    class Logger {
    public:
        enum class LogLevel {
            TRACE,
            DEBUG,
            INFO,
            WARN,
            ERROR,
            FATAL,
        };
        Logger(const std::string_view& file, int line);
        Logger(const std::string_view& file, int line, LogLevel level);
        Logger(const std::string_view& file, int line, LogLevel level, const char* func);
        Logger(const std::string_view& file, int line, bool toAbort);
        ~Logger();

        detail::LogStream& Stream() { return m_fmt.m_strm; }
        static LogLevel Level();

        class SetLogLevel;

        static void SetOutput(void (*)(const char* msg, const uint64_t len));
        static void SetFlush(void (*)());
        static void SetTimeZone(bool isLocal) { s_isLocalTimeZone = isLocal; }

    private:
        class Formatter {
        public:
            using LogLevel = Logger::LogLevel;
            Formatter(LogLevel level, int old_errno, std::string_view file, int line);
            void FormatTime();
            void Finish();

            Timestamp m_time;  // 要格式化的时间戳
            detail::LogStream m_strm;
            LogLevel m_level;         // 要格式化的日志等级
            int m_line;               // 要格式化的行号
            const char* m_fileName;   // 要格式化的日志名
            uint64_t m_fileNameSize;  // 日志名的长度
        };

    private:
        static bool s_isLocalTimeZone;  // 日志是否采用本地时区
        Formatter m_fmt;                // 要格式器
    };

    namespace detail {
        void DefaultOutput(const char* msg, const uint64_t len);
        void DefaultFlush();
        Logger::LogLevel InitLogLevel();
    }  // namespace detail

    namespace process {
        pid_t Pid();
        std::string PidString();
        uid_t Uid();
        std::string UserName();
        Timestamp StartTime();
        int ClockTicksPerSecond();
        int PageSize();


        // read /proc/self/status
        std::string ProcStatus();  // read /proc/self/stat
        std::string ProcStat();    // read /proc/self/task/tid/stat
        std::string ThreadStat();  // readlink /proc/self/exe
        std::string ExePath();
        std::string HostName();
        std::string_view ProcName(const std::string& stat);
        std::string ProcName();

        int OpenedFiles();
        int MaxOpenFiles();
        int ThreadNum();

        std::vector<pid_t> Threads();

    }  // namespace process

    class SyncLogFile : detail::uncopyable {
    public:
        SyncLogFile(const std::string& filename, uint64_t rollSize, bool isLocalTimeZone, bool threadSafe = true, int flushInterval = 3, int checkEveryN = 1024)
            : m_filename(filename), k_RollSize(rollSize), k_FlushInterval(flushInterval), k_CheckEveryN(checkEveryN), m_isLocalTimeZone(isLocalTimeZone), m_mu(threadSafe ? std::make_unique<std::mutex>() : NULL) { Roll(); }
        ~SyncLogFile() = default;
        void Append(const char* logline, const uint64_t len);
        void Flush();
        bool Roll();

    private:
        void AppendUnlocked(const char* logline, const uint64_t len);
        std::string MakeLogFileName(const std::string& basename, const Timestamp& now);

        const std::string m_filename;
        const uint64_t k_RollSize;  //   多少byte就roll一次
        const int k_FlushInterval;  // 多少秒就flush一次
        const int k_CheckEveryN;    // 每写入N次就强制检查一次，与m_count配合使用

        bool m_isLocalTimeZone;  // 是否使用本地时区
        int m_count = 0;         // 记录被写入的次数，与k_CheckEveryN配合使用
        time_t m_day;            // 第几天
        time_t m_lastRoll = 0;   // 上次roll的时间
        time_t m_lastFlush = 0;  // 上次flush的时间
        std::unique_ptr<std::mutex> m_mu;
        std::unique_ptr<detail::LogFileAppender> m_appender;
        static const int k_OneDaySeconds = 60 * 60 * 24;  // 一天有多少秒
    };

    class AsyncLogFile : detail::uncopyable {
    public:
        AsyncLogFile(const std::string& basename, int64_t rollSize, bool isLocalTimeZone = false, int flushInterval = 3);
        ~AsyncLogFile();

        void Append(const char* logline, uint64_t len);
        void Stop();

    private:
        using FixedBuf = detail::FixedBuffer<detail::k_LargeBuf>;
        using BufVector = std::vector<std::unique_ptr<FixedBuf>>;
        using BufPtr = BufVector::value_type;
        // m_thrd在此函数内循环
        void Handle();

    private:
        const int k_flushInterval;             // 多少秒就flush一次
        bool m_isLocalTimeZone;                // 是否使用本地时区
        std::atomic_bool m_isRunning = false;  // 是否已运行
        const std::string m_fileName;
        const int64_t m_rollSize;  //  多少byte就roll一次
        detail::Thread m_thrd;
        detail::CountDownLatch m_latch = detail::CountDownLatch(1);
        std::mutex m_mu;
        std::condition_variable m_fullCond;  // 前端的buf是否已满
        BufPtr m_thisBuf;                    // 前端用的buf
        BufPtr m_nextBuf;                    // 前端的备用buf
        BufVector m_bufs;                    // 后端用的buf
    };



#define LOG_TRACE \
    if (kurisu::Logger::Level() <= kurisu::Logger::LogLevel::TRACE) \
    kurisu::Logger(__FILE__, __LINE__, kurisu::Logger::LogLevel::TRACE, __func__).Stream()
#define LOG_DEBUG \
    if (kurisu::Logger::Level() <= kurisu::Logger::LogLevel::DEBUG) \
    kurisu::Logger(__FILE__, __LINE__, kurisu::Logger::LogLevel::DEBUG, __func__).Stream()
#define LOG_INFO \
    if (kurisu::Logger::Level() <= kurisu::Logger::LogLevel::INFO) \
    kurisu::Logger(__FILE__, __LINE__).Stream()
#define LOG_WARN kurisu::Logger(__FILE__, __LINE__, kurisu::Logger::LogLevel::WARN).Stream()
#define LOG_ERROR kurisu::Logger(__FILE__, __LINE__, kurisu::Logger::LogLevel::ERROR).Stream()
#define LOG_FATAL kurisu::Logger(__FILE__, __LINE__, kurisu::Logger::LogLevel::FATAL).Stream()
#define LOG_SYSERR kurisu::Logger(__FILE__, __LINE__, false).Stream()
#define LOG_SYSFATAL kurisu::Logger(__FILE__, __LINE__, true).Stream()






    class SockAddr : detail::copyable {
    public:
        SockAddr() = default;
        explicit SockAddr(uint16_t port, const char* host = "0.0.0.0");
        explicit SockAddr(const sockaddr& addr) : sa(addr) {}
        explicit SockAddr(const sockaddr_in& addr) : sin(addr) {}
        explicit SockAddr(const sockaddr_in6& addr) : sin6(addr) {}

        sockaddr& As_sockaddr() { return sa; }
        sockaddr_in& As_sockaddr_in() { return sin; }
        sockaddr_in6& As_sockaddr_in6() { return sin6; }

        sa_family_t Famliy() const { return sa.sa_family; }
        std::string ipString() const;
        std::string ipPortString() const;
        uint16_t HostPort() const;
        uint16_t NetPort() const;

        void SetScopeID(uint32_t scope_id) { sin6.sin6_scope_id = scope_id; }

    private:
        union {
            sockaddr sa;
            sockaddr_in sin;
            sockaddr_in6 sin6;
        };
    };

    namespace detail {
        socklen_t SizeofSockAddr(SockAddr* addr);
        int MakeNonblockingSocket(sa_family_t family);
        int Connect(int sockfd, SockAddr* addr);
        void Bind(int sockfd, SockAddr* addr);
        void Listen(int sockfd);
        int Accept(int sockfd, SockAddr* addr);

        void Close(int sockfd);
        void ShutdownWrite(int sockfd);
        void IpProtToAddr(uint16_t port, const char* host, SockAddr* addr);
        void AddrToIp(char* buf, uint64_t size, SockAddr* addr);
        void AddrToIpPort(char* buf, uint64_t size, SockAddr* addr);
        int GetSocketError(int sockfd);
        SockAddr GetLocalAddr(int sockfd);
        SockAddr GetPeerAddr(int sockfd);
        int MakeNonblockingTimerfd();
        timespec HowMuchTimeFromNow(Timestamp when);
        void ResetTimerfd(int timerfd, Timestamp runtime);

        class Socket : uncopyable {
        public:
            explicit Socket(int sockfd) : m_fd(sockfd) {}

            // Socket(Socket&&) // move constructor in C++11
            ~Socket() { detail::Close(m_fd); }

            int fd() const { return m_fd; }
            // return true if success.
            bool GetTcpInfo(struct tcp_info*) const;
            bool GetTcpInfoString(char* buf) const;

            /// abort if address in use
            void bind(SockAddr* addr) { detail::Bind(m_fd, addr); }
            /// abort if address in use
            void listen() { detail::Listen(m_fd); }

            /// On success, returns a non-negative integer that is
            /// a descriptor for the accepted socket, which has been
            /// set to non-blocking and close-on-exec. *peeraddr is assigned.
            /// On error, -1 is returned, and *peeraddr is untouched.
            int accept(SockAddr* peeraddr) { return detail::Accept(m_fd, peeraddr); }

            void ShutdownWrite() { detail::ShutdownWrite(m_fd); }

            /// Enable/disable TCP_NODELAY (disable/enable Nagle's algorithm).
            void SetTcpNoDelay(bool on);

            /// Enable/disable SO_REUSEADDR
            void SetReuseAddr(bool on);

            /// Enable/disable SO_REUSEPORT
            void SetReusePort(bool on);

            /// Enable/disable SO_KEEPALIVE
            // void setKeepAlive(bool on);

        private:
            const int m_fd;
        };


        class Timer : uncopyable {
        public:
            Timer(std::function<void()> cb, Timestamp when, double interval)
                : m_runtime(when), m_interval(interval), m_isRepeat(interval > 0.0), m_callback(std::move(cb)) {}

            void Run() const { m_callback(); }
            void Restart()
            {
                // 如果是重复的定时器
                if (m_isRepeat)
                    m_runtime = Timestamp::AddTime(m_runtime, m_interval);  // 重新计算下一个超时时刻
                else
                    m_runtime = Timestamp::Invalid();
            }

            Timestamp GetRuntime() const { return m_runtime; }
            bool IsRepeat() const { return m_isRepeat; }



        private:
            Timestamp m_runtime;                     // 超时的时刻(理想状态下回调函数运行的时刻)
            const double m_interval;                 // 触发超时的间隔,为0则代表是一次性定时器
            const bool m_isRepeat;                   // 是否重复
            const std::function<void()> m_callback;  // 定时器回调函数
        };


        class Channel;
        class Poller;
        class TimerQueue;
        class ShutdownTimingWheel;
        class HeartbeatTimingWheel;

    }  // namespace detail

    class TimerID : detail::copyable {
    public:
        explicit TimerID(detail::Timer* timer) : m_timer(timer) {}

    private:
        std::pair<Timestamp, detail::Timer*> Key() { return std::make_pair(m_timer->GetRuntime(), m_timer); }
        detail::Timer* m_timer;
        friend class detail::TimerQueue;
    };

    class TcpConnection;

    class EventLoop : detail::uncopyable {
    public:
        EventLoop();
        ~EventLoop();
        void Loop();
        // 可以跨线程调用，如果在其他线程调用，会调用wakeup保证退出
        void Quit();
        Timestamp GetReturnTime() const { return m_returnTime; }
        int64_t GetLoopNum() const { return m_loopNum; }
        // 在EventLoop所属的线程中执行此函数
        void Run(std::function<void()> callback);
        // 注册只执行一次的额外任务
        void AddTask(std::function<void()> callback);
        // 某时刻触发Timer
        TimerID RunAt(Timestamp time, std::function<void()> callback);
        // 多久后触发Timer,单位second
        TimerID RunAfter(double delay, std::function<void()> callback);
        // 每隔多久触发Timer,单位second
        TimerID RunEvery(double interval, std::function<void()> callback);
        // 取消定时器
        void Cancel(TimerID timerID);

        uint64_t GetTasksNum() const;
        // 唤醒阻塞在poll的loop
        void Wakeup();
        // 注册channel到poller的map中
        void UpdateChannel(detail::Channel* channel);
        // 从poller的map中移除channel
        void RemoveChannel(detail::Channel* channel);
        // m_poller中是否有channel
        bool HasChannel(detail::Channel* channel);
        pid_t GetThreadID() const { return m_threadID; }
        // 断言此线程是相应的IO线程
        void AssertInLoopThread();
        // 此线程是否是相应的IO线程
        bool InLoopThread() const { return m_threadID == this_thrd::Tid(); }
        // 是否正在调用回调函数
        bool IsRunningCallback() const { return m_isRunningCallback; }
        // 将此TcpConnection加入到ShutdownTimingWheel中
        void AddShutdown(const std::shared_ptr<TcpConnection>& conn);
        // 更新此TcpConnection,以防ShutdownTimingWheelTimingWheel时间到调用Shutdown
        void UpdateShutdown(const std::shared_ptr<TcpConnection>& conn);

        void AddHeartbeat(const std::shared_ptr<TcpConnection>& conn);

        void SetShutdownTimingWheel(int interval) { m_shutdownInterval = interval; }
        void SetHeartbeatTimingWheel(int interval) { m_heartbeatInterval = interval; }
        // 获取此线程的EventLoop
        static EventLoop* GetLoopOfThisThread();

    private:
        void WakeUpRead();
        void RunTasks();

        // DEBUG用的,打印每个事件
        void PrintActiveChannels() const;

        bool m_isLooping = false;           // 线程是否调用了Loop()
        bool m_isRunningCallback = false;   // 线程是否正在执行回调函数
        bool m_isRunningTasks = false;      //  EventLoop线程是否正在执行的额外任务
        std::atomic_bool m_isQuit = false;  // 线程是否调用了Quit()
        int m_wakeUpfd;                     // 一个eventfd   用于唤醒阻塞在Poll的Loop
        int m_shutdownInterval = 0;
        int m_heartbeatInterval = 0;
        const pid_t m_threadID;
        detail::Channel* m_thisActiveChannel = nullptr;  // 当前正在执行哪个channel的回调函数
        int64_t m_loopNum = 0;                           // Loop总循环次数
        Timestamp m_returnTime;                          // 有事件到来时返回的时间戳
        std::unique_ptr<detail::Poller> m_poller;
        std::unique_ptr<detail::TimerQueue> timerQueue_;   // Timer队列
        std::unique_ptr<detail::Channel> m_wakeUpChannel;  // 用于退出时唤醒loop
        std::unique_ptr<detail::ShutdownTimingWheel> m_shutdownTimingWheel;
        std::unique_ptr<detail::HeartbeatTimingWheel> m_heartbeatTimingWheel;
        std::vector<detail::Channel*> m_activeChannels;  // 保存所有有事件到来的channel

        // EventLoop线程每次轮询除了执行有事件到来的channel的回调函数外，也会执行这个vector内的函数（额外的任务）
        std::vector<std::function<void()>> m_waitingTasks;
        std::vector<std::function<void()>> m_runningTasks;
        mutable std::mutex m_mu;  // 保护Tasks
    };

    namespace detail {
        // 当前线程EventLoop对象指针

        int CreateEventfd();
        void ReadTimerfd(int timerfd, Timestamp now);

        class EventLoopThread : uncopyable {
        public:
            EventLoopThread(int shutdownInterval = 0,
                            int heartbeatInterval = 0,
                            const std::function<void(EventLoop*)>& threadInitCallback = std::function<void(EventLoop*)>(),
                            const std::string& name = std::string())
                : m_shutdownInterval(shutdownInterval),
                  m_heartbeatInterval(heartbeatInterval),
                  m_thrd(std::bind(&EventLoopThread::Handle, this), name),
                  m_threadInitCallback(threadInitCallback) {}

            ~EventLoopThread();

            EventLoop* Start();

        private:
            void Handle();

            EventLoop* m_loop = nullptr;
            bool m_isExiting = false;
            int m_shutdownInterval;
            int m_heartbeatInterval;
            Thread m_thrd;
            std::mutex m_mu;
            std::condition_variable m_cond;
            std::function<void(EventLoop*)> m_threadInitCallback;
        };

        class EventLoopThreadPool : uncopyable {
        public:
            EventLoopThreadPool(EventLoop* loop, const std::string& name);
            void SetThreadNum(int threadNum) { m_thrdNum = threadNum; }
            void Start(int shutdownInterval = 0,
                       int heartbeatInterval = 0,
                       const std::function<void(EventLoop*)>& threadInitCallback = std::function<void(EventLoop*)>());
            EventLoop* GetNextLoop();
            EventLoop* GetLoopRandom();
            std::vector<EventLoop*> GetAllLoops();
            bool Started() const { return m_isStarted; }
            const std::string& Name() const { return m_name; }

        private:
            EventLoop* m_loop;
            std::string m_name;
            bool m_isStarted = false;
            int m_thrdNum = 0;
            int m_next = 0;
            std::vector<std::unique_ptr<EventLoopThread>> m_thrds;
            std::vector<EventLoop*> m_loops;
        };

        class Channel : uncopyable {
        public:
            Channel(EventLoop* loop, int fd) : m_fd(fd), m_loop(loop) {}
            // 处理事件
            void RunCallback(Timestamp timestamp);
            // 设置可读事件回调函数
            void SetReadCallback(std::function<void(Timestamp)> callback) { m_readCallback = std::move(callback); }
            // 设置可写事件回调函数
            void SetWriteCallback(std::function<void()> callback) { m_writeCallback = std::move(callback); }
            // 设置关闭事件回调函数
            void SetCloseCallback(std::function<void()> callback) { m_closeCallback = std::move(callback); }
            // 设置错误事件回调函数
            void SetErrorCallback(std::function<void()> callback) { m_errorCallback = std::move(callback); }

            // 用于延长某些对象的生命期,使其寿命与obj相同
            void Tie(const std::shared_ptr<void>&);
            int fd() const { return m_fd; }
            // 返回注册的事件
            int GetEvents() const { return m_events; }
            // 设置就绪的事件
            void SetRevents(int revents) { m_revents = revents; }

            // 是否未注册事件
            bool IsNoneEvent() const { return m_events == k_NoneEvent; }

            // 注册可读事件
            void OnReading();
            // 注销读事件
            void OffReading();
            // 注册写事件
            void OnWriting();
            // 注销写事件
            void OffWriting();
            // 注销所有事件
            void OffAll();
            // 是否已注册可读事件
            bool IsReading() const { return m_events & k_ReadEvent; }
            // 是否已注册写事件
            bool IsWriting() const { return m_events & k_WriteEvent; }
            // New=-1   Added=1   Deleted=2
            int GetStatus() { return m_status; }
            // New=-1   Added=1   Deleted=2
            void SetStatus(int status) { m_status = status; }

            // DEBUG 用
            std::string ReventsString() const { return EventsToString(m_fd, m_revents); }
            // DEBUG 用
            std::string EventsString() const { return EventsToString(m_fd, m_events); }

            // 是否生成EPOLLHUP事件的日志
            void OnLogHup() { m_logHup = true; }
            // 是否生成EPOLLHUP事件的日志
            void OffLogHup() { m_logHup = false; }
            // 返回所属的EventLoop
            EventLoop* GetLoop() { return m_loop; }
            // 暂时离开所属的EventLoop
            void Remove();

        private:
            static std::string EventsToString(int fd, int ev);
            // 加入所属的EventLoop
            void Update();
            // 处理到来的事件
            void RunCallbackWithGuard(Timestamp timestamp);

            static const int k_NoneEvent = 0;                   // 无事件
            static const int k_ReadEvent = EPOLLIN | EPOLLPRI;  // 可读
            static const int k_WriteEvent = EPOLLOUT;           // 可写

            bool m_isTied = false;             //  是否将生命周期绑定到了外部，使生命周期与外部对象相同
            bool m_isRunningCallback = false;  // 是否处于处理事件中
            bool m_isInLoop = false;           // 是否已在EventLoop里注册
            bool m_logHup = true;              // EPOLLHUP时是否生成日志

            const int m_fd;     // 此channel负责管理的文件描述符
            int m_events = 0;   // 注册的事件
            int m_revents = 0;  // 被poller设置的就绪的事件
            int m_status = -1;  // 在poller中的状态
            EventLoop* m_loop;  // 指向此channel所属的EventLoop

            std::weak_ptr<void> m_tie;                      // 用来绑定obj以修改生命周期
            std::function<void(Timestamp)> m_readCallback;  // 读事件回调函数
            std::function<void()> m_writeCallback;          // 写事件回调函数
            std::function<void()> m_closeCallback;          // 关闭事件回调函数
            std::function<void()> m_errorCallback;          // 错误事件回调函数
        };

        class Poller : uncopyable {
        public:
            Poller(EventLoop* loop) : m_epollfd(epoll_create1(EPOLL_CLOEXEC)), m_loop(loop), m_events(k_InitEventListSize) {}
            ~Poller() = default;
            // 对epoll_wait的封装,返回时间戳
            Timestamp Poll(int timeoutMs, std::vector<Channel*>* activeChannels);
            // 添加channel
            void UpdateChannel(Channel* channel);
            // 移除channel
            void RemoveChannel(Channel* channel);
            // 这个channel是否在ChannelMap中
            bool HasChannel(Channel* channel) const;
            // 断言此线程是相应的IO线程
            void AssertInLoopThread() const { m_loop->AssertInLoopThread(); }



        private:
            static const int k_New = -1;
            static const int k_Added = 1;
            static const int k_Deleted = 2;
            static const int k_InitEventListSize = 16;  // epoll事件表的大小

            static const char* OperationString(int operatoin);
            // 注册事件,由operation决定
            void Update(int operation, Channel* channel);

            int m_epollfd;
            EventLoop* m_loop;                   // 指向所属的EventLoop
            std::vector<epoll_event> m_events;   // epoll事件数组
            std::map<int, Channel*> m_channels;  // 存储channel的map
        };

        class TimerQueue : uncopyable {
        private:
            using Key = std::pair<Timestamp, detail::Timer*>;
            using TimerMap = std::map<Key, std::unique_ptr<detail::Timer>>;
            using TimeoutTimer = std::vector<std::unique_ptr<detail::Timer>>;

        public:
            explicit TimerQueue(EventLoop* loop);
            ~TimerQueue();
            // 可以跨线程调用
            TimerID Add(std::function<void()> callback, Timestamp when, double interval);
            // 可以跨线程调用
            void Cancel(TimerID id) { m_loop->Run(std::bind(&TimerQueue::CancelInLoop, this, id)); }

        private:
            // 以下成员函数只可能在TimerQueue所属的IO线程调用，因而不用加锁

            void AddInLoop(detail::Timer* timer);
            void CancelInLoop(TimerID timerID);

            // 当Timer触发超时时回调此函数
            void Handle();
            // 返回超时的Timer
            TimeoutTimer GetTimeout(Timestamp now);
            // 重置非一次性的Timer
            void Reset(TimeoutTimer& timeout);
            // 向TimerMap中插入timer
            bool Insert(detail::Timer* timer);

            bool m_isRunningCallback = false;
            const int m_timerfd;
            EventLoop* m_loop;                     // TimerQueue所属的EventLoop
            std::vector<TimerID> m_cancelledSoon;  // 即将被cancel的timer
            TimerMap m_timers;
            Channel m_timerfdChannel;
        };

        class Acceptor : uncopyable {
        public:
            Acceptor(EventLoop* loop, const SockAddr& listenAddr, bool reuseport);
            ~Acceptor();
            void SetConnectionCallback(const std::function<void(int sockfd, const SockAddr&)>& cb)
            {
                m_connectionCallback = cb;
            }
            void Listen();
            bool Listening() const { return m_isListening; }

        private:
            // 处理事件
            void Handle();

            EventLoop* m_loop;
            detail::Socket m_sock;
            Channel m_channel;
            std::function<void(int sockfd, const SockAddr&)> m_connectionCallback;
            bool m_isListening;
            int m_voidfd;  // 空闲的fd,用于处理fd过多的情况
        };


        template <typename CLASS, typename... ARGS>
        class WeakCallback {
        public:
            WeakCallback(const std::weak_ptr<CLASS>& obj, const std::function<void(CLASS*, ARGS...)>& func)
                : m_obj(obj), m_func(func) {}
            void operator()(ARGS&&... args) const
            {
                std::shared_ptr<CLASS> ptr(m_obj.lock());
                if (ptr)
                    m_func(ptr.get(), std::forward<ARGS>(args)...);
            }

        private:
            std::weak_ptr<CLASS> m_obj;
            std::function<void(CLASS*, ARGS...)> m_func;
        };

        template <typename CLASS, typename... ARGS>
        WeakCallback<CLASS, ARGS...> MakeWeakCallback(const std::shared_ptr<CLASS>& object, void (CLASS::*function)(ARGS...))
        {
            return WeakCallback<CLASS, ARGS...>(object, function);
        }

        template <typename CLASS, typename... ARGS>
        WeakCallback<CLASS, ARGS...> MakeWeakCallback(const std::shared_ptr<CLASS>& object, void (CLASS::*function)(ARGS...) const)
        {
            return WeakCallback<CLASS, ARGS...>(object, function);
        }

    }  // namespace detail

    class Buffer : detail::copyable {
    private:
        struct Buf {
            uint64_t len;
            char* ptr[0];  // 柔性数组成员，它将在运行时被分配大小
        };

    public:
        static const uint64_t k_PrependSize = 8;
        static const uint64_t k_InitSize = 1024;

        explicit Buffer(uint64_t initialSize = k_InitSize) : m_readIndex(k_PrependSize), m_writeIndex(k_PrependSize)
        {
            m_buf = std::unique_ptr<Buf>((Buf*)operator new(sizeof(Buf) + k_PrependSize + initialSize));
            m_buf->len = k_PrependSize + initialSize;
        }

        // 顺便把移动构造也实现了
        Buffer(Buffer&& other) : m_readIndex(other.m_readIndex), m_writeIndex(other.m_writeIndex), m_buf(std::move(other.m_buf))
        {
        }

        // 因为成员有unique_ptr，所以要手动实现拷贝构造
        Buffer(const Buffer& other) : m_readIndex(other.m_readIndex), m_writeIndex(other.m_writeIndex)
        {
            m_buf = std::unique_ptr<Buf>((Buf*)operator new(sizeof(Buf) + other.m_buf->len));
            m_buf->len = other.m_buf->len;
            std::copy(other.m_buf->ptr, other.m_buf->ptr + other.m_buf->len, m_buf->ptr);
        }


        void Swap(Buffer& other);
        void Resize(uint64_t size);
        uint64_t Size() { return m_buf->len - k_PrependSize; }
        void Clear() { m_readIndex = m_writeIndex = k_PrependSize; }

        uint64_t ReadableBytes() const { return m_writeIndex - m_readIndex; }
        uint64_t WriteableBytes() const { return m_buf->len - m_writeIndex; }
        uint64_t PrependableBytes() const { return m_readIndex; }


        const char* FindCRLF() const;
        const char* FindCRLF(const char* start) const;
        const char* FindEOL() const { return (const char*)memchr(ReadIndex(), '\n', ReadableBytes()); }
        const char* FindEOL(const char* start) const { return (const char*)memchr(start, '\n', WriteIndex() - start); }

        void Discard(uint64_t len);
        void DiscardUntil(const char* end) { Discard(end - ReadIndex()); }
        void DiscardInt64() { Discard(sizeof(int64_t)); }
        void DiscardInt32() { Discard(sizeof(int)); }
        void DiscardInt16() { Discard(sizeof(int16_t)); }
        void DiscardInt8() { Discard(sizeof(int8_t)); }
        void DiscardAll() { m_readIndex = m_writeIndex = k_PrependSize; }

        std::string RetrieveAllAsString() { return RetrieveAsString(ReadableBytes()); }
        std::string RetrieveAsString(uint64_t len);

        std::string_view ToStringView() const { return std::string_view(ReadIndex(), ReadableBytes()); }
        std::string ToString() const { return std::string(ReadIndex(), ReadableBytes()); }

        void Append(const char* data, uint64_t len);
        void Append(const void* data, uint64_t len) { Append((const char*)data, len); }
        void Append(const std::string_view& str) { Append(str.data(), str.size()); }
        void AppendInt64(int64_t x);
        void AppendInt32(int x);
        void AppendInt16(int16_t x);
        void AppendInt8(int8_t x) { Append(&x, sizeof(x)); }
        void AppendFloat(float x);
        void AppendDouble(double x);

        const char* ReadIndex() const { return Begin() + m_readIndex; }
        char* WriteIndex() { return Begin() + m_writeIndex; }
        const char* WriteIndex() const { return Begin() + m_writeIndex; }

        int64_t ReadInt64();
        int ReadInt32();
        int16_t ReadInt16();
        int8_t ReadInt8();
        float ReadFloat();
        double ReadDouble();

        int64_t PeekInt64() const;
        int PeekInt32() const;
        int16_t PeekInt16() const;
        int8_t PeekInt8() const { return *ReadIndex(); }
        float PeekFloat() const;
        double PeekDouble() const;

        void PrependInt64(int64_t x);
        void PrependInt32(int x);
        void PrependInt16(int16_t x);
        void PrependInt8(int8_t x) { Prepend(&x, sizeof(x)); }
        void PrependFloat(float x);
        void PrependDouble(double x);

        void Shrink(uint64_t reserve);

        uint64_t Capacity() const { return m_buf->len; }

        ssize_t ReadSocket(int fd, int* savedErrno);
        void ReadIndexRightShift(uint64_t len) { m_readIndex += len; }
        void ReadIndexLeftShift(uint64_t len) { m_readIndex -= len; }
        void WriteIndexRightShift(uint64_t len) { m_writeIndex += len; }
        void WriteIndexLeftShift(uint64_t len) { m_writeIndex -= len; }

    private:
        void Prepend(const void* data, uint64_t len);
        void EnsureWritableBytes(uint64_t len);
        char* Begin() { return (char*)m_buf->ptr; }
        const char* Begin() const { return (const char*)m_buf->ptr; }
        void MakeSpace(uint64_t len);



    private:
        uint64_t m_readIndex;   // 从这里开始读
        uint64_t m_writeIndex;  // 从这里开始写
        std::unique_ptr<Buf> m_buf;

        static const char k_CRLF[];
    };

    class LengthCodec : detail::copyable {
    public:
        class LengthCodecException : public Exception {
        public:
            LengthCodecException(std::string msg) : Exception(std::move(msg)) {}
        };

        LengthCodec() = default;
        LengthCodec(int maxFrameLength, int lengthFieldOffset, int lengthFieldLength, int lengthAdjustment, int initialBytesToStrip);

        bool IsComplete(Buffer* buf);

        Buffer Decode(Buffer* buf);

    private:
        void Fail(int64_t frameLength);
        void FailIfNecessary(bool firstDetectionOfTooLongFrame);
        int64_t PeekBodyLength(Buffer* buf);
        void DiscardingTooLongFrame(Buffer* buf);

    private:
        int m_maxFrameLength;
        int m_lengthFieldOffset;
        int m_lengthFieldLength;
        int m_lengthAdjustment;
        int m_lengthFieldEndOffset;
        int m_initialBytesToStrip;
        int m_frameLengthInt;
        friend TcpConnection;
    };

    class TcpConnection : detail::uncopyable, public std::enable_shared_from_this<TcpConnection> {
    public:
        TcpConnection(EventLoop* loop, const std::string& name, int sockfd, const SockAddr& localAddr, const SockAddr& peerAddr);
        ~TcpConnection();
        // 获取所在的EventLoop
        EventLoop* GetLoop() const { return m_loop; }
        // 获取名称
        const std::string& Name() const { return m_name; }
        // 本地地址
        const SockAddr& LocalAddr() const { return m_localAddr; }
        // 远端地址
        const SockAddr& PeerAddr() const { return m_peerAddr; }
        // 是否已连接
        bool Connected() const { return m_status == k_Connected; }
        // 是否已断开连接
        bool Disconnected() const { return m_status == k_Disconnected; }
        // return true if success.
        bool GetTcpInfo(struct tcp_info* tcpi) const;
        std::string GetTcpInfoString() const;

        void Send(std::string&& msg);  // C++11
        void Send(const void* data, int len) { Send(std::string_view((const char*)data, len)); }
        void Send(const std::string_view& msg);
        void Send(Buffer* buf);
        // 线程安全，muduo源码中的注释错了
        void Shutdown();
        // 线程安全
        void ForceClose();
        void ForceCloseWithDelay(double seconds);
        // 设置TcpNoDelay
        void SetTcpNoDelay(bool on) { m_socket->SetTcpNoDelay(on); }

        void StartRead() { m_loop->Run(std::bind(&TcpConnection::StartReadInLoop, this)); }
        void StopRead() { m_loop->Run(std::bind(&TcpConnection::StopReadInLoop, this)); }
        // 线程不安全
        bool IsReading() const { return m_isReading; }
        // 连接建立 销毁 产生关闭事件时 都会调用这个回调函数
        void SetConnectionCallback(const std::function<void(const std::shared_ptr<TcpConnection>&)>& callback) { m_connCallback = callback; }
        // 接收到数据之后会调用这个回调函数
        void SetMessageCallback(const std::function<void(const std::shared_ptr<TcpConnection>&, Buffer*, Timestamp)>& callback)
        {
            m_msgCallback = callback;
        }
        // 写操作完成时会调用这个回调函数
        void SetWriteCompleteCallback(const std::function<void(const std::shared_ptr<TcpConnection>&)>& callback)
        {
            m_writeCompleteCallback = callback;
        }

        Buffer* GetInputBuffer() { return &m_inputBuf; }
        Buffer* GetOutputBuffer() { return &m_outputBuf; }

        void SetCloseCallback(const std::function<void(const std::shared_ptr<TcpConnection>&)>& callback)
        {
            m_closeCallback = callback;
        }

        // 当TcpServer accept一个连接时会调用这个函数
        void ConnectEstablished();
        // 当TcpServer remove一个连接或自身析构时会调用这个函数
        void ConnectDestroyed();

        void SetAny(std::any& any) { m_any = any; }
        void SetAny(std::any&& any) { m_any = std::move(any); }
        const std::any& GetAny() const { return m_any; }
        std::any& GetAny() { return m_any; }

        void AddToShutdownTimingWheel();

        void SetLengthCodec(LengthCodec* decoder) { m_decoder = *decoder; }

    private:
        void UpdateShutdownTimingWheel();
        void HandleRead(Timestamp receiveTime);
        void HandleWrite();
        void HandleClose();
        void HandleError();
        void SendStringView(const std::string_view& msg) { SendInLoop(msg.data(), msg.size()); }
        void SendInLoop(const void* message, uint64_t len);
        void ShutdownInLoop();
        void ForceCloseInLoop();
        const char* StatusToString() const;
        void StartReadInLoop();
        void StopReadInLoop();

    private:
        static const int k_Disconnected = 0;
        static const int k_Connecting = 1;
        static const int k_Connected = 2;
        static const int k_Disconnecting = 3;

        bool m_isReading;                        // 是否正在read
        bool m_isInShutdownTimingWheel = false;  // 是否已在ShutdownTimingWheel中
        std::atomic_int m_status;                // 连接的状态
        EventLoop* m_loop;                       // 所属的EventLoop
        std::unique_ptr<detail::Socket> m_socket;
        std::unique_ptr<detail::Channel> m_channel;
        LengthCodec m_decoder;
        Buffer m_inputBuf;
        Buffer m_outputBuf;
        std::any m_any;
        const SockAddr m_localAddr;  // 本地地址
        const SockAddr m_peerAddr;   // 对端地址
        const std::string m_name;    // 名称
        std::function<void(const std::shared_ptr<TcpConnection>&)> m_connCallback;
        std::function<void(const std::shared_ptr<TcpConnection>&, Buffer*, Timestamp)> m_msgCallback;
        std::function<void(const std::shared_ptr<TcpConnection>&)> m_writeCompleteCallback;
        std::function<void(const std::shared_ptr<TcpConnection>&)> m_closeCallback;
    };

    class TcpServer : detail::uncopyable {
    public:
        enum Option {
            k_NoReusePort,
            k_ReusePort,
        };

        TcpServer(EventLoop* loop, const SockAddr& listenAddr, const std::string& name, Option option = k_NoReusePort);
        ~TcpServer();

        const std::string& ipPort() const { return m_ipPort; }
        const std::string& Name() const { return m_name; }
        EventLoop* GetLoop() const { return m_loop; }
        // must be called before Start
        void SetThreadNum(int num) { m_threadPool->SetThreadNum(num); }
        // must be called before Start
        void SetThreadInitCallback(const std::function<void(EventLoop*)>& callback) { m_threadInitCallback = callback; }
        // must be called before Start
        void SetTcpNoDelay(bool on) { m_isTcpNoDelay = on; }
        // must be called before Start
        void SetShutdownInterval(int interval) { m_shutdownInterval = interval; }
        // must be called before Start
        void SetHeartbeatInterval(int interval) { m_heartbeatInterval = interval; }
        // must be called before Start
        void SetHeartbeatMsg(const void* data, int len);

        // must be called before Start
        // lengthFieldLength only supports 1/2/4/8
        void SetLengthCodec(int maxFrameLength, int lengthFieldOffset, int lengthFieldLength, int lengthAdjustment, int initialBytesToStrip);

        // must be called after Start
        std::shared_ptr<detail::EventLoopThreadPool> GetThreadPool() { return m_threadPool; }

        // start,thread safe
        void Start();
        // must be called before Start
        // set the callback when connection active
        void SetConnectionCallback(const std::function<void(const std::shared_ptr<TcpConnection>&)>& callback)
        {
            m_connCallback = callback;
        }
        // must be called before Start
        // set the callback when msg arrive
        void SetMessageCallback(const std::function<void(const std::shared_ptr<TcpConnection>&, Buffer*, Timestamp)>& callback)
        {
            m_msgCallback = callback;
        }
        // must be called before Start
        // set the callback when all msg write complete
        void SetWriteCompleteCallback(const std::function<void(const std::shared_ptr<TcpConnection>&)>& callback)
        {
            m_writeCompleteCallback = callback;
        }


    private:
        using ConnectionMap = std::map<std::string, std::shared_ptr<TcpConnection>>;
        // 连接到来时会回调的函数
        void NewConnection(int sockfd, const SockAddr& peerAddr);
        // 将这个TcpConnection从map中删除,线程安全
        void RemoveConnection(const std::shared_ptr<TcpConnection>& conn);
        // 将这个TcpConnection从map中删除
        void RemoveConnectionInLoop(const std::shared_ptr<TcpConnection>& conn);

    private:
        bool m_isTcpNoDelay = false;
        std::atomic_bool m_isStarted = false;
        int m_nextConnID;
        int m_shutdownInterval = 0;
        int m_heartbeatInterval = 0;
        std::unique_ptr<detail::Acceptor> m_acceptor;
        EventLoop* m_loop;  // TcpServer所属的EventLoop
        std::shared_ptr<detail::EventLoopThreadPool> m_threadPool;
        LengthCodec m_decoder;
        const std::string m_ipPort;
        const std::string m_name;
        std::function<void(const std::shared_ptr<TcpConnection>&)> m_connCallback;                     // 连接到来执行的回调函数
        std::function<void(const std::shared_ptr<TcpConnection>&, Buffer*, Timestamp)> m_msgCallback;  // 消息到来执行的回调函数
        std::function<void(const std::shared_ptr<TcpConnection>&)> m_writeCompleteCallback;            // 写操作完成时执行的回调函数
        std::function<void(EventLoop*)> m_threadInitCallback;
        ConnectionMap m_connections;
    };

    namespace detail {
        class ShutdownTimingWheel {
        private:
            class Entry {
            public:
                explicit Entry(std::weak_ptr<TcpConnection> weak) : m_weak(weak) {}

                ~Entry()
                {
                    // 不调用Shutdown是因为，Shutdown是防止客户端的数据没有被读完
                    // 而在这里肯定已经很久没消息了，所以直接强制关闭
                    if (auto conn = m_weak.lock(); conn)
                        conn->ForceClose();
                }

            private:
                std::weak_ptr<TcpConnection> m_weak;
            };

        public:
            // second
            ShutdownTimingWheel(EventLoop* loop, int interval)
            {
                loop->RunEvery(1.0, [this, interval] {
                    m_buckets.push_back(Bucket());
                    if (m_buckets.size() > (uint64_t)interval)
                        m_buckets.pop_front();
                });
            }
            void PushAndSetAny(const std::shared_ptr<TcpConnection>& conn)
            {
                auto entry = std::make_shared<Entry>(conn);
                conn->SetAny(std::weak_ptr<Entry>(entry));
                m_buckets.back().insert(std::move(entry));
            }
            void Update(const std::shared_ptr<TcpConnection>& conn)
            {
                auto weak = std::any_cast<std::weak_ptr<Entry>>(conn->GetAny());
                if (auto entry = weak.lock(); entry)
                    m_buckets.back().insert(std::move(entry));
            }

        private:
            using Bucket = std::set<std::shared_ptr<Entry>>;
            std::deque<Bucket> m_buckets;
        };

        class HeartbeatTimingWheel {
        public:
            class Msg {
            public:
                static char* data() { return m_msg.get(); }
                static int len() { return m_len; }
                static void SetMsg(const void* data, int len)
                {
                    m_len = len;
                    m_msg = std::unique_ptr<char>(new char[len]);
                    memcpy(m_msg.get(), (char*)data, len);
                }

            private:
                static int m_len;
                static std::unique_ptr<char> m_msg;
            };

            // second
            HeartbeatTimingWheel(EventLoop* loop, int interval) : m_buckets(interval)
            {
                loop->RunEvery(1.0, std::bind(&HeartbeatTimingWheel::OnTimer, this));
            }

            void Add(const std::shared_ptr<TcpConnection>& conn) { m_buckets[m_index].push_back(conn); }


        private:
            void OnTimer()
            {
                Bucket& list = m_buckets[m_index++];
                // LOG_INFO << "Heartbeat:" << m_index - 1 << ":" << list.size();
                if (m_index >= (int)m_buckets.size())
                    m_index = 0;
                auto it = list.rbegin();  // 从后往前遍历,减少删除时的拷贝
                while (it != list.rend())
                {
                    if (auto conn = it->lock(); conn)  // 还活着就发
                    {
                        conn->Send(Msg::data(), Msg::len());
                        ++it;
                    }
                    else  // 死了就删
                        list.erase((++it).base());
                }
            }

        private:
            // TODO  试了一下,在即使删中间vector还是比list快,更何况list遍历还慢,先观察
            using Bucket = std::vector<std::weak_ptr<TcpConnection>>;
            int m_index = 0;
            std::vector<Bucket> m_buckets;
        };


        void DefaultConnCallback(const std::shared_ptr<kurisu::TcpConnection>& conn);
        void DefaultMsgCallback(const std::shared_ptr<kurisu::TcpConnection>&, kurisu::Buffer* buf, kurisu::Timestamp);
    }  // namespace detail

}  // namespace kurisu
