#pragma once
#include <string>
#include <string.h>
#include <string_view>
#include <boost/operators.hpp>
#include <fmt/chrono.h>
#include <fmt/compile.h>
#include <execinfo.h>
#include <cxxabi.h>
#include <sys/syscall.h>
#include <chrono>
#include <pthread.h>
#include <functional>
#include <sys/prctl.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <deque>
#include <pwd.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/resource.h>  //rlimit
#include <sys/times.h>     //tms
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/uio.h>  // readv
#include <sys/timerfd.h>
#include <netinet/tcp.h>  //tcp_info
#include <unistd.h>
#include <netdb.h>  //addrinfo
#include <signal.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <map>

inline uint64_t htonll(uint64_t val) { return htobe64(val); }
inline uint64_t ntohll(uint64_t val) { return be64toh(val); }

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

    class Timestamp : detail::copyable, boost::totally_ordered<Timestamp> {
    public:
        Timestamp() : m_stamp(std::chrono::system_clock::now()) {}
        explicit Timestamp(std::chrono::system_clock::time_point stamp) : m_stamp(stamp) {}

        auto GetStamp() const { return m_stamp; }
        void swap(Timestamp& other) { std::swap(m_stamp, other.m_stamp); }
        bool valid() { return m_stamp != s_invalid; }
        char* GmLogFormat(char* buf) const;
        char* LocalLogFormat(char* buf) const;
        //format gmtime
        std::string GmFormatString() const { return fmt::format(FMT_COMPILE("{:%F %T}"), fmt::gmtime(m_stamp)); }
        //format localtime
        std::string LocalFormatString() const { return fmt::format(FMT_COMPILE("{:%F %T}"), fmt::localtime(m_stamp)); }
        int64_t usSinceEpoch() const;
        int64_t nsSinceEpoch() const;
        int64_t secondsSinceEpoch() const;
        time_t as_time_t() { return (time_t)secondsSinceEpoch(); }

        bool operator<(const Timestamp& other) const { return this->GetStamp() < other.GetStamp(); }
        bool operator==(const Timestamp& other) const { return this->GetStamp() == other.GetStamp(); }

        static Timestamp now() { return Timestamp(); }
        static Timestamp invalid() { return Timestamp(s_invalid); }
        //seconds
        static double TimeDifference(Timestamp high, Timestamp low);
        static Timestamp AddTime(Timestamp stamp, double second);

    private:
        static const std::chrono::system_clock::time_point s_invalid;
        std::chrono::system_clock::time_point m_stamp;
    };
    inline const std::chrono::system_clock::time_point Timestamp::s_invalid;

    namespace this_thrd {
        namespace detail {
            inline pid_t gettid() { return (pid_t)syscall(SYS_gettid); }
            inline std::string Demangle(const char* symbol)
            {
                uint64_t size;
                int status;
                char buf[256] = {0};
                char* demangled = nullptr;  //指向解析后的信息

                const char* left = nullptr;
                const char* right = symbol;
                while (*right != '\0')
                    if (*right++ == '(')
                        left = right;
                    else if (*right == '+')
                        break;

                if (*right == '+')
                {
                    memcpy(buf, left, (uint64_t)(right - left));
                    if (demangled = abi::__cxa_demangle(buf, NULL, &size, &status); demangled != nullptr)  //解析成功
                    {
                        std::string res(symbol, left);
                        res += demangled;
                        res += right;
                        free(demangled);
                        return res;
                    }
                }
                //不需要解析
                return symbol;
            }
        }  // namespace detail

        inline __thread int t_cachedTid;  //tid的缓存，提高效率(不用每次都调用系统函数)
        inline __thread char t_tidString[32];
        inline __thread int t_tidStringLength;
        inline __thread const char* t_threadName;

        inline void cacheTid()
        {
            if (t_cachedTid == 0)
            {
                t_cachedTid = detail::gettid();
                char* p = fmt::format_to(t_tidString, FMT_COMPILE("{:5d}"), t_cachedTid);
                t_tidStringLength = (int)(p - t_tidString);
            }
        }
        inline int tid()
        {
            if (t_cachedTid == 0)
                cacheTid();
            return t_cachedTid;
        }
        inline const char* TidString() { return t_tidString; }
        inline int TidStringLength() { return t_tidStringLength; }
        inline const char* name() { return t_threadName; }

        inline bool IsMainThread() { return tid() == getpid(); }
        inline void SleepFor(int us) { std::this_thread::sleep_for(std::chrono::microseconds(us)); }
        inline std::string StackTrace()
        {
            std::string stack;
            const int len = 200;
            void* buf[len];
            int n = backtrace(buf, len);  //将信息的地址(void*)传入buf中,返回地址个数

            char** msgs = backtrace_symbols(buf, n);  //将地址(void*)转成字符数组(char*),用于打印

            if (msgs)
            {
                for (int i = 0; i < n; ++i)
                {
                    //以msgs[i]遍历所有信息
                    stack += detail::Demangle(msgs[i]);
                    stack += '\n';
                }
                free(msgs);
            }
            return stack;
        }

        namespace detail {
            inline bool mainThreadInit = [] {
                t_threadName = "main";
                cacheTid();
                pthread_atfork(NULL, NULL, [] {
                    t_threadName = "main";
                    t_cachedTid = 0;
                    cacheTid();
                });
                return 0;
            }();
        }
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
            KnownLengthString(const char* str, uint64_t len) : buf(str), size(len) {}
            KnownLengthString& operator=(const KnownLengthString& other)
            {
                buf = other.buf;
                size = other.size;
                return *this;
            }
            const char* buf;
            uint64_t size;
        };

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


        class ThreadData : uncopyable {
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

        constexpr uint64_t k_SmallBuf = 4'000;
        constexpr uint64_t k_LargeBuf = 4'000'000;
        template <uint64_t SIZE>
        class FixedBuffer : uncopyable {
        public:
            FixedBuffer() : m_index(m_data) { m_data[SIZE] = '\0'; }

            uint64_t size() const { return (uint64_t)(m_index - m_data); }
            const char* data() const { return m_data; }
            void IndexShiftRight(uint64_t num) { m_index += num; }
            char* index() { return m_index; }
            void reset() { m_index = m_data; }
            void zero() { memset(m_data, 0, SIZE); }
            std::string String() const { return std::string(m_data, size()); }
            std::string_view StringView() const { return std::string_view(m_data, size()); }
            uint64_t AvalibleSize() { return (uint64_t)(end() - m_index); }

            void append(const char* buf, uint64_t len)
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
            const char* end() const { return m_data + SIZE; }


        private:
            char m_data[SIZE + 1];
            char* m_index;
        };


        //效率很高的itoa算法，比to_string快5倍以上
        template <typename T>
        inline uint64_t convert(char buf[], T value)
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
        //效率很高的pointer->str算法
        inline uint64_t convertHex(char buf[], uintptr_t value)
        {
            static const char digitsHex[] = "0123456789ABCDEF";
            uintptr_t i = value;
            char* p = buf;

            do
            {
                int lsd = (int)(i % 16);
                i /= 16;
                *p++ = digitsHex[lsd];
            } while (i != 0);

            *p = '\0';
            std::reverse(buf, p);

            return p - buf;
        }

        //用于读小于64KB的文件
        class ReadSmallFile : uncopyable {
        public:
            ReadSmallFile(StringArg filepath);
            ~ReadSmallFile();
            //把文件的数据读到传进来的std::string里 返回errno
            int ReadToString(int maxSize, std::string& content, int64_t* fileSize, int64_t* modifyTime, int64_t* createTime);
            //把文件的数据读到m_buf里  返回errno
            int ReadToBuffer(int* size);
            const char* buffer() const { return m_buf; }

            static const int k_BufferSize = 64 * 1024;  //byte

        private:
            int m_fd;
            int m_err;
            char m_buf[k_BufferSize];
        };

        inline ReadSmallFile::ReadSmallFile(StringArg filepath) : m_fd(open(filepath.c_str(), O_RDONLY | O_CLOEXEC)), m_err(0)
        {
            m_buf[0] = '\0';
            if (m_fd < 0)
                m_err = errno;
        }
        inline ReadSmallFile::~ReadSmallFile()
        {
            if (m_fd >= 0)
                close(m_fd);
        }
        inline int ReadSmallFile::ReadToString(int maxSize, std::string& content, int64_t* fileSize, int64_t* modifyTime, int64_t* createTime)
        {
            int err = m_err;
            if (m_fd >= 0)
            {
                content.clear();
                if (fileSize)
                {
                    struct stat statbuf;
                    if (fstat(m_fd, &statbuf) == 0)
                    {
                        if (S_ISREG(statbuf.st_mode))
                        {
                            *fileSize = statbuf.st_size;
                            content.reserve((int)std::min((int64_t)maxSize, *fileSize));
                        }
                        else if (S_ISDIR(statbuf.st_mode))
                            err = EISDIR;
                        if (modifyTime)
                            *modifyTime = statbuf.st_mtime;
                        if (createTime)
                            *createTime = statbuf.st_ctime;
                    }
                    else
                        err = errno;
                }

                while (content.size() < (uint64_t)maxSize)
                {
                    uint64_t toRead = std::min((uint64_t)maxSize - content.size(), sizeof(m_buf));
                    ssize_t n = read(m_fd, m_buf, toRead);
                    if (n > 0)
                        content.append(m_buf, n);
                    else
                    {
                        if (n < 0)
                            err = errno;
                        break;
                    }
                }
            }
            return err;
        }
        inline int ReadSmallFile::ReadToBuffer(int* size)
        {
            int err = m_err;
            if (m_fd >= 0)
            {
                ssize_t n = pread(m_fd, m_buf, sizeof(m_buf) - 1, 0);
                if (n >= 0)
                {
                    if (size)
                        *size = (int)n;
                    m_buf[n] = '\0';
                }
                else
                    err = errno;
            }
            return err;
        }

        //将filepath对应的文件读到传进来的std::string里
        inline int ReadFile(StringArg filepath, int maxSize, std::string& content, int64_t* fileSize = nullptr, int64_t* modifyTime = nullptr, int64_t* createTime = nullptr)
        {
            ReadSmallFile file(filepath);
            return file.ReadToString(maxSize, content, fileSize, modifyTime, createTime);
        }

        inline __thread int t_numOpenedFiles = 0;
        inline int FdDirFilter(const struct dirent* d)
        {
            if (isdigit(d->d_name[0]))
                ++t_numOpenedFiles;
            return 0;
        }

        inline __thread std::vector<pid_t>* t_pids = nullptr;
        inline int TaskDirFilter(const struct dirent* d)
        {
            if (isdigit(d->d_name[0]))
                detail::t_pids->emplace_back(atoi(d->d_name));
            return 0;
        }

        inline int ScanDir(const char* dirpath, int (*filter)(const struct dirent*))
        {
            struct dirent** namelist = nullptr;
            return scandir(dirpath, &namelist, filter, alphasort);
        }

        inline Timestamp g_startTime = Timestamp::now();
        // assume those won't change during the life time of a process.
        inline int g_clockTicks = (int)sysconf(_SC_CLK_TCK);
        inline int g_pageSize = (int)sysconf(_SC_PAGE_SIZE);

        inline __thread char t_errnobuf[512];  //缓存errno的str
        inline __thread char t_time[64];       //缓存时间的str
        inline __thread int64_t t_lastSecond;  //上次缓存t_time的时间
        //生成errno的str
        inline const char* strerror_tl(int savedErrno) { return strerror_r(savedErrno, t_errnobuf, sizeof(t_errnobuf)); }

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


        class Thread : uncopyable {
        public:
            explicit Thread(std::function<void()> func, const std::string& name = std::string())
                : m_func(std::move(func)), m_name(name) { SetDefaultName(); }
            ~Thread();

            void start();
            void join() { m_thrd.join(); }

            bool started() const { return m_started; }
            pid_t tid() const { return m_tid; }
            const std::string& name() const { return m_name; }

            static int numCreated() { return s_createdNum; }

        private:
            void SetDefaultName();

            bool m_started = 0;
            pthread_t m_pthreadID = 0;
            pid_t m_tid = 0;
            std::function<void()> m_func;
            std::string m_name;
            detail::CountDownLatch m_latch = detail::CountDownLatch(1);
            std::thread m_thrd;
            static std::atomic_int32_t s_createdNum;
        };
        inline std::atomic_int32_t Thread::s_createdNum = 0;

        inline Thread::~Thread()
        {
            if (m_started && m_thrd.joinable())
                m_thrd.detach();
        }
        inline void Thread::SetDefaultName()
        {
            ++s_createdNum;
            if (m_name.empty())
                m_name = fmt::format("Thread{}", s_createdNum);
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



        class ThreadPool : uncopyable {
        public:
            explicit ThreadPool(const std::string& name = "ThreadPool") : m_name(name) {}
            ~ThreadPool();
            //这个函数的调用必须在SetThrdNum前，用于设置等待队列的大小
            void SetMaxQueueSize(int maxSize) { m_maxSize = maxSize; }
            //设置线程池的大小
            void SetThrdNum(int thrdNum);
            //设置创建线程池时会调用的初始化函数
            void SetThreadInitCallback(const std::function<void()>& callback) { m_thrdInitCallBack = callback; }

            void stop();
            //在线程池内执行该函数
            void run(std::function<void()> func);
            void join();

            const std::string& name() const { return m_name; }
            uint64_t size() const;

        private:
            //线程不安全，这个函数必须在m_mu已被锁上时才能调用
            //当 m_maxSize == 0时恒为不满
            bool full() const;
            //线程池在这个函数中循环
            void Loop();
            std::function<void()> take();

        private:
            std::atomic_bool m_running = 0;  //退出的标志
            uint64_t m_maxSize = 0;
            std::string m_name;
            mutable std::mutex m_mu;
            std::condition_variable m_notEmptyCond;
            std::condition_variable m_notFullCond;
            std::function<void()> m_thrdInitCallBack;
            std::vector<std::unique_ptr<Thread>> m_thrds;
            std::deque<std::function<void()>> m_task;
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
                m_thrds.emplace_back(std::make_unique<Thread>(std::bind(&kurisu::detail::ThreadPool::Loop, this), m_name + id));  //创建线程
                m_thrds[i]->start();
            }

            if (thrdNum == 0 && m_thrdInitCallBack)  //如果创建的线程为0，也执行初始化后的回调函数
                m_thrdInitCallBack();
        }
        inline void ThreadPool::Loop()
        {
            try
            {
                if (m_thrdInitCallBack)
                    m_thrdInitCallBack();  //如果有初始化的回调函数就执行
                while (m_running)
                    if (std::function<void()> func(take()); func)  //从函数队列中拿出函数，是可执行的函数就执行，直到m_running被变成false
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
        inline std::function<void()> ThreadPool::take()
        {
            std::unique_lock locker(m_mu);
            if (m_task.empty() && m_running)
                m_notEmptyCond.wait(locker, [this] { return !m_task.empty() || !m_running; });  //等到有任务为止

            std::function<void()> func;
            if (!m_task.empty())
            {
                func = std::move(m_task.front());  //取出函数
                m_task.pop_front();
            }
            if (m_maxSize > 0)
                m_notFullCond.notify_one();  //如果对等待队列做了大小限制，就通知其他线程，等待队列有空闲了

            return func;
        }
        inline void ThreadPool::run(std::function<void()> task)
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
            detail::CountDownLatch latch(1);

            //往线程池里加入一个倒计时任务
            run(std::bind(&kurisu::detail::CountDownLatch::CountDown, &latch));

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



        class LogStream : uncopyable {
        public:
            using Buf = detail::FixedBuffer<detail::k_SmallBuf>;

            void append(const char* data, int len) { m_buf.append(data, len); }
            const Buf& buffer() const { return m_buf; }
            void ResetBuffer() { m_buf.reset(); }

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
            LogStream& operator<<(const Buf& buf);
            LogStream& operator<<(const detail::KnownLengthString& str);

        private:
            template <class T>
            void FormatInt(T val);

        private:
            Buf m_buf;
            static const int k_MaxSize = 32;  //除const char* std::strubg std::string_view之外，一次能写入的最大字节数
        };

        inline LogStream& LogStream::operator<<(bool val)
        {
            m_buf.append(val ? "1" : "0", 1);
            return *this;
        }
        inline LogStream& LogStream::operator<<(char val)
        {
            m_buf.append(&val, 1);
            return *this;
        }
        inline LogStream& LogStream::operator<<(int16_t val)
        {
            *this << (int)val;
            return *this;
        }
        inline LogStream& LogStream::operator<<(uint16_t val)
        {
            *this << (uint32_t)val;
            return *this;
        }
        inline LogStream& LogStream::operator<<(int val)
        {
            FormatInt(val);
            return *this;
        }
        inline LogStream& LogStream::operator<<(uint32_t val)
        {
            FormatInt(val);
            return *this;
        }
        inline LogStream& LogStream::operator<<(int64_t val)
        {
            FormatInt(val);
            return *this;
        }
        inline LogStream& LogStream::operator<<(uint64_t val)
        {
            FormatInt(val);
            return *this;
        }
        inline LogStream& LogStream::operator<<(float val)
        {
            *this << (double)val;
            return *this;
        }
        inline LogStream& LogStream::operator<<(double val)
        {
            if (m_buf.AvalibleSize() >= k_MaxSize)
            {
                auto ptr = fmt::format_to(m_buf.index(), FMT_COMPILE("{:.12g}"), val);
                uint64_t len = ptr - m_buf.index();
                m_buf.IndexShiftRight(len);
            }
            return *this;
        }
        inline LogStream& LogStream::operator<<(const void* p)
        {
            uintptr_t val = (uintptr_t)p;
            if (m_buf.AvalibleSize() >= k_MaxSize)
            {
                char* buf = m_buf.index();
                buf[0] = '0';
                buf[1] = 'x';
                uint64_t len = detail::convertHex(buf + 2, val);
                m_buf.IndexShiftRight(len + 2);
            }
            return *this;
        }
        inline LogStream& LogStream::operator<<(const char* p)
        {
            if (p)
                m_buf.append(p, strlen(p));
            else
                m_buf.append("(null)", 6);
            return *this;
        }
        inline LogStream& LogStream::operator<<(const unsigned char* p)
        {
            *this << (const char*)p;
            return *this;
        }
        inline LogStream& LogStream::operator<<(const std::string& str)
        {
            m_buf.append(str.data(), str.size());
            return *this;
        }
        inline LogStream& LogStream::operator<<(const std::string_view& str)
        {
            m_buf.append(str.data(), str.size());
            return *this;
        }
        inline LogStream& LogStream::operator<<(const Buf& buf)
        {
            *this << buf.StringView();
            return *this;
        }
        inline LogStream& LogStream::operator<<(const detail::KnownLengthString& str)
        {
            m_buf.append(str.buf, str.size);
            return *this;
        }
        template <class T>
        inline void LogStream::FormatInt(T val)
        {
            if (m_buf.AvalibleSize() >= k_MaxSize)
            {
                uint64_t len = detail::convert(m_buf.index(), val);
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

        detail::LogStream& stream() { return m_fmt.m_strm; }
        static LogLevel level();

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
            void finish();

            Timestamp m_time;  //要格式化的时间戳
            detail::LogStream m_strm;
            LogLevel m_level;         //要格式化的日志等级
            int m_line;               //要格式化的行号
            const char* m_fileName;   //要格式化的日志名
            uint64_t m_fileNameSize;  //日志名的长度
        };

    private:
        static bool s_isLocalTimeZone;  //日志是否采用本地时区
        Formatter m_fmt;                //要格式器
    };
    inline bool Logger::s_isLocalTimeZone = false;

    namespace detail {
        inline void DefaultOutput(const char* msg, const uint64_t len) { fwrite(msg, 1, len, stdout); }
        inline void DefaultFlush() { fflush(stdout); }
        inline Logger::LogLevel InitLogLevel()
        {
            if (getenv("KURISU_LOG_TRACE"))
                return Logger::LogLevel::TRACE;
            else if (getenv("KURISU_LOG_DEBUG"))
                return Logger::LogLevel::DEBUG;
            else
                return Logger::LogLevel::INFO;
        }

        inline void (*g_output)(const char* msg, const uint64_t len) = DefaultOutput;
        inline void (*g_flush)() = DefaultFlush;
        inline Logger::LogLevel g_logLevel = InitLogLevel();
        inline const char* LogLevelName[6] = {
            "[TRACE] ",
            "[DEBUG] ",
            "[INFO]  ",
            "[WARN]  ",
            "[ERROR] ",
            "[FATAL] ",
        };

    }  // namespace detail

    namespace process {
        inline pid_t pid() { return getpid(); }
        inline std::string PidString() { return fmt::format("{}", pid()); }
        inline uid_t uid() { return getuid(); }
        inline std::string UserName()
        {
            struct passwd pwd;
            struct passwd* result = nullptr;
            char buf[8192];
            const char* name = "unknownuser";

            getpwuid_r(uid(), &pwd, buf, sizeof buf, &result);
            if (result)
                name = pwd.pw_name;
            return name;
        }
        inline Timestamp StartTime() { return detail::g_startTime; }
        inline int ClockTicksPerSecond() { return detail::g_clockTicks; }
        inline int PageSize() { return detail::g_pageSize; }


        // read /proc/self/status
        inline std::string ProcStatus()
        {
            std::string result;
            detail::ReadFile("/proc/self/status", 65536, result);
            return result;
        }
        // read /proc/self/stat
        inline std::string ProcStat()
        {
            std::string result;
            detail::ReadFile("/proc/self/stat", 65536, result);
            return result;
        }
        // read /proc/self/task/tid/stat
        inline std::string ThreadStat()
        {
            char buf[64];
            fmt::format_to(buf, "/proc/self/task/{}/stat", this_thrd::tid());
            std::string result;
            detail::ReadFile(buf, 65536, result);
            return result;
        }
        // readlink /proc/self/exe
        inline std::string ExePath()
        {
            std::string result;
            char buf[1024];
            ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf));
            if (n > 0)
                result.assign(buf, n);
            return result;
        }

        inline std::string HostName()
        {
            char buf[256];
            if (gethostname(buf, sizeof buf) == 0)
            {
                buf[sizeof(buf) - 1] = '\0';
                return buf;
            }
            else
                return "unknownhost";
        }
        inline std::string_view ProcName(const std::string& stat)
        {
            std::string_view name;
            uint64_t lp = stat.find('(');
            uint64_t rp = stat.rfind(')');
            if (lp != std::string_view::npos && rp != std::string_view::npos && lp < rp)
                name = std::string_view(stat.data() + lp + 1, (int)(rp - lp - 1));
            return name;
        }
        inline std::string ProcName() { return ProcName(ProcStat()).data(); }

        inline int OpenedFiles()
        {
            using namespace detail;
            t_numOpenedFiles = 0;
            ScanDir("/proc/self/fd", FdDirFilter);
            return t_numOpenedFiles;
        }
        inline int MaxOpenFiles()
        {
            struct rlimit rl;
            if (getrlimit(RLIMIT_NOFILE, &rl))
                return OpenedFiles();
            else
                return (int)rl.rlim_cur;
        }

        inline int ThreadNum()
        {
            int result = 0;
            std::string status = ProcStatus();
            size_t pos = status.find("Threads:");
            if (pos != std::string::npos)
                result = atoi(status.c_str() + pos + 8);
            return result;
        }

        inline std::vector<pid_t> threads()
        {
            std::vector<pid_t> result;
            detail::t_pids = &result;
            detail::ScanDir("/proc/self/task", detail::TaskDirFilter);
            detail::t_pids = NULL;
            std::sort(result.begin(), result.end());
            return result;
        }

    }  // namespace process

    class SyncLogFile : detail::uncopyable {
    public:
        SyncLogFile(const std::string& filename, uint64_t rollSize, bool isLocalTimeZone, bool threadSafe = true, int flushInterval = 3, int checkEveryN = 1024)
            : m_filename(filename), k_RollSize(rollSize), k_FlushInterval(flushInterval), k_CheckEveryN(checkEveryN), m_isLocalTimeZone(isLocalTimeZone), m_mu(threadSafe ? std::make_unique<std::mutex>() : NULL) { roll(); }
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

    class AsyncLogFile : detail::uncopyable {
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
        detail::Thread m_thrd;
        detail::CountDownLatch m_latch = detail::CountDownLatch(1);
        std::mutex m_mu;
        std::condition_variable m_fullCond;  //前端的buf是否已满
        BufPtr m_thisBuf;                    //前端用的buf
        BufPtr m_nextBuf;                    //前端的备用buf
        BufVector m_bufs;                    //后端用的buf
    };



#define LOG_TRACE \
    if (kurisu::Logger::level() <= kurisu::Logger::LogLevel::TRACE) \
    kurisu::Logger(__FILE__, __LINE__, kurisu::Logger::LogLevel::TRACE, __func__).stream()
#define LOG_DEBUG \
    if (kurisu::Logger::level() <= kurisu::Logger::LogLevel::DEBUG) \
    kurisu::Logger(__FILE__, __LINE__, kurisu::Logger::LogLevel::DEBUG, __func__).stream()
#define LOG_INFO \
    if (kurisu::Logger::level() <= kurisu::Logger::LogLevel::INFO) \
    kurisu::Logger(__FILE__, __LINE__).stream()
#define LOG_WARN kurisu::Logger(__FILE__, __LINE__, kurisu::Logger::LogLevel::WARN).stream()
#define LOG_ERROR kurisu::Logger(__FILE__, __LINE__, kurisu::Logger::LogLevel::ERROR).stream()
#define LOG_FATAL kurisu::Logger(__FILE__, __LINE__, kurisu::Logger::LogLevel::FATAL).stream()
#define LOG_SYSERR kurisu::Logger(__FILE__, __LINE__, false).stream()
#define LOG_SYSFATAL kurisu::Logger(__FILE__, __LINE__, true).stream()






    class SockAddr : detail::copyable {
    public:
        SockAddr() = default;
        explicit SockAddr(uint16_t port, const char* host = "0.0.0.0");
        explicit SockAddr(const sockaddr& addr) : sa(addr) {}
        explicit SockAddr(const sockaddr_in& addr) : sin(addr) {}
        explicit SockAddr(const sockaddr_in6& addr) : sin6(addr) {}

        sockaddr& as_sockaddr() { return sa; }
        sockaddr_in& as_sockaddr_in() { return sin; }
        sockaddr_in6& as_sockaddr_in6() { return sin6; }

        sa_family_t famliy() const { return sa.sa_family; }
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
        inline socklen_t SizeofSockAddr(SockAddr* addr)
        {
            if (addr->famliy() == AF_INET)
                return sizeof(struct sockaddr_in);
            else
                return sizeof(struct sockaddr_in6);
        }

        inline int MakeNonblockingSocket(sa_family_t family)
        {
            int sockfd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
            if (sockfd < 0)
                LOG_SYSFATAL << "Socket::MakeNonblockingSocket";
            return sockfd;
        }
        inline int Connect(int sockfd, SockAddr* addr) { return connect(sockfd, &addr->as_sockaddr(), SizeofSockAddr(addr)); }
        inline void Bind(int sockfd, SockAddr* addr)
        {
            if (int res = bind(sockfd, &addr->as_sockaddr(), SizeofSockAddr(addr)); res < 0)
                LOG_SYSFATAL << "Socket::BindAndListen  bind";
        }
        inline void Listen(int sockfd)
        {
            if (int res = listen(sockfd, SOMAXCONN); res < 0)
                LOG_SYSFATAL << "Socket::BindAndListen  listen";
        }
        inline int Accept(int sockfd, SockAddr* addr)
        {
            socklen_t addrlen = sizeof(*addr);

            //将fd直接设为非阻塞
            //FIXME  IPv6可以吗
            int connfd = accept4(sockfd, &addr->as_sockaddr(), &addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (connfd < 0)
            {
                int savedErrno = errno;
                LOG_SYSERR << "Socket::Accept";
                switch (savedErrno)
                {
                    case EAGAIN:
                    case ECONNABORTED:
                    case EINTR:
                    case EPROTO:  // ???
                    case EPERM:
                    case EMFILE:  // per-process lmit of open file desctiptor ???
                        // expected errors
                        errno = savedErrno;
                        break;
                    case EBADF:
                    case EFAULT:
                    case EINVAL:
                    case ENFILE:
                    case ENOBUFS:
                    case ENOMEM:
                    case ENOTSOCK:
                    case EOPNOTSUPP:
                        // unexpected errors
                        LOG_FATAL << "unexpected error of ::accept " << savedErrno;
                        break;
                    default:
                        LOG_FATAL << "unknown error of ::accept " << savedErrno;
                        break;
                }
            }
            return connfd;
        }

        inline ssize_t Read(int sockfd, void* buf, uint64_t count) { return read(sockfd, buf, count); }

        inline ssize_t Readv(int sockfd, const struct iovec* iov, int iovcnt) { return readv(sockfd, iov, iovcnt); }

        inline ssize_t Write(int sockfd, const void* buf, uint64_t count) { return write(sockfd, buf, count); }

        inline void Close(int sockfd)
        {
            if (close(sockfd) < 0)
                LOG_SYSERR << "Sockets::Close";
        }

        inline void ShutdownWrite(int sockfd)
        {
            if (shutdown(sockfd, SHUT_WR) < 0)
                LOG_SYSERR << "Sockets::ShutdownWrite";
        }

        inline void IpProtToAddr(uint16_t port, const char* host, SockAddr* addr)
        {
            // addr->sin_port = htons(port);
            sockaddr_in& sin = addr->as_sockaddr_in();
            sockaddr_in6& sin6 = addr->as_sockaddr_in6();

            if (inet_pton(AF_INET, host, &sin.sin_addr) == 1)  //IPv4
                sin.sin_family = AF_INET;
            else if (inet_pton(AF_INET6, host, &sin6.sin6_addr) == 1)  //IPv6
                sin6.sin6_family = AF_INET6;
            else  //host
            {
                addrinfo* ais = NULL;
                int ret = getaddrinfo(host, NULL, NULL, &ais);
                if (ret != 0 || ais == NULL || ais->ai_addrlen == 0 || ais->ai_addr == NULL)
                {
                    LOG_SYSERR << "Socket::IpProtToAddr host resolve";
                    return;
                }
                memcpy(&addr->as_sockaddr(), ais->ai_addr, ais->ai_addrlen);
                freeaddrinfo(ais);
            }
            if (addr->famliy() == AF_INET)
                sin.sin_port = htons(port);
            else
                sin6.sin6_port = htons(port);
        }

        inline void AddrToIp(char* buf, uint64_t size, SockAddr* addr)
        {
            if (addr->famliy() == AF_INET)
                inet_ntop(AF_INET, &addr->as_sockaddr_in().sin_addr, buf, (socklen_t)size);
            else if (addr->famliy() == AF_INET6)
                inet_ntop(AF_INET6, &addr->as_sockaddr_in6().sin6_addr, buf, (socklen_t)size);
        }

        inline void AddrToIpPort(char* buf, uint64_t size, SockAddr* addr)
        {
            if (addr->famliy() == AF_INET)
            {
                AddrToIp(buf, size, addr);
                uint64_t end = strlen(buf);
                uint16_t port = addr->HostPort();
                // snprintf(buf + end, size - end, ":%u", port);
                fmt::format_to(buf + end, ":{}", port);
            }
            else
            {
                buf[0] = '[';
                AddrToIp(buf + 1, size - 1, addr);
                uint64_t end = strlen(buf);
                uint16_t port = addr->HostPort();
                // snprintf(buf + end, size - end, "]:%u", port);
                fmt::format_to(buf + end, "]:{}", port);
            }
        }

        inline int GetSocketError(int sockfd)
        {
            int optval;
            socklen_t optlen = sizeof(optval);

            if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) < 0)
                return errno;
            else
                return optval;
        }

        inline SockAddr GetLocalAddr(int sockfd)
        {
            SockAddr localaddr;
            memset(&localaddr, 0, sizeof(SockAddr));
            socklen_t addrlen = sizeof(SockAddr);
            if (getsockname(sockfd, &localaddr.as_sockaddr(), &addrlen) < 0)
                LOG_SYSERR << "Sockets::GetLocalAddr";
            return localaddr;
        }
        inline SockAddr GetPeerAddr(int sockfd)
        {
            SockAddr peeraddr;
            memset(&peeraddr, 0, sizeof(SockAddr));
            socklen_t addrlen = sizeof(SockAddr);
            if (getpeername(sockfd, &peeraddr.as_sockaddr(), &addrlen) < 0)
                LOG_SYSERR << "Sockets::GetPeerAddr";
            return peeraddr;
        }


        //FIXME   待测试
        inline bool IsSelfConnect(int sockfd)
        {
            SockAddr localaddr = GetLocalAddr(sockfd);
            SockAddr peeraddr = GetPeerAddr(sockfd);
            if (localaddr.famliy() == AF_INET)
            {
                sockaddr_in& local = localaddr.as_sockaddr_in();
                sockaddr_in& peer = peeraddr.as_sockaddr_in();
                return local.sin_port == peer.sin_port && local.sin_addr.s_addr == peer.sin_addr.s_addr;
            }
            else if (localaddr.famliy() == AF_INET6)
            {
                sockaddr_in6& local = localaddr.as_sockaddr_in6();
                sockaddr_in6& peer = peeraddr.as_sockaddr_in6();
                return local.sin6_port == peer.sin6_port &&
                       memcmp(&local.sin6_addr, &peer.sin6_addr, sizeof(local.sin6_addr)) == 0;
            }
            else
                return false;
        }

        inline int MakeNonblockingTimerfd()
        {
            int timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
            if (timerfd < 0)
                LOG_SYSFATAL << "Failed in MakeNonblockingTimerfd";
            return timerfd;
        }

        inline timespec HowMuchTimeFromNow(Timestamp when)
        {
            Timestamp now;
            int64_t ns = when.nsSinceEpoch() - now.nsSinceEpoch();
            timespec ts;
            ts.tv_sec = (time_t)(ns / 1'000'000'000);
            ts.tv_nsec = ns % 1'000'000'000;
            return ts;
        }

        inline int ResetTimerfd(int timerfd, Timestamp runtime)
        {
            itimerspec newValue;
            itimerspec oldValue;
            memset(&newValue, 0, sizeof(newValue));
            memset(&oldValue, 0, sizeof(oldValue));
            newValue.it_value = HowMuchTimeFromNow(runtime);

            return timerfd_settime(timerfd, 0, &newValue, &oldValue);
        }


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
        inline bool Socket::GetTcpInfo(tcp_info* tcpi) const
        {
            socklen_t len = sizeof(*tcpi);
            memset(tcpi, 0, len);
            return getsockopt(m_fd, SOL_TCP, TCP_INFO, tcpi, &len) == 0;
        }
        inline bool Socket::GetTcpInfoString(char* buf) const
        {
            tcp_info tcpi;
            bool ok = GetTcpInfo(&tcpi);
            if (ok)
            {
                fmt::format_to(buf, "unrecovered={} "
                                    "rto={} ato={} snd_mss={} rcv_mss={} "
                                    "lost={} retrans={} rtt={} rttvar={} "
                                    "sshthresh={} cwnd={} total_retrans={}",
                               tcpi.tcpi_retransmits,  // Number of unrecovered [RTO] timeouts
                               tcpi.tcpi_rto,          // Retransmit timeout in usec
                               tcpi.tcpi_ato,          // Predicted tick of soft clock in usec
                               tcpi.tcpi_snd_mss,
                               tcpi.tcpi_rcv_mss,
                               tcpi.tcpi_lost,     // Lost packets
                               tcpi.tcpi_retrans,  // Retransmitted packets out
                               tcpi.tcpi_rtt,      // Smoothed round trip time in usec
                               tcpi.tcpi_rttvar,   // Medium deviation
                               tcpi.tcpi_snd_ssthresh,
                               tcpi.tcpi_snd_cwnd,
                               tcpi.tcpi_total_retrans);  // Total retransmits for entire connection
            }
            return ok;
        }
        inline void Socket::SetTcpNoDelay(bool on)
        {
            int optval = on ? 1 : 0;
            setsockopt(m_fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
        }
        inline void Socket::SetReuseAddr(bool on)
        {
            int optval = on ? 1 : 0;
            setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
        }
        inline void Socket::SetReusePort(bool on)
        {
#ifdef SO_REUSEPORT
            int optval = on ? 1 : 0;
            int ret = setsockopt(m_fd, SOL_SOCKET, SO_REUSEPORT,
                                 &optval, sizeof(optval));
            if (ret < 0 && on)
            {
                LOG_SYSERR << "SO_REUSEPORT failed.";
            }
#else
            if (on)
            {
                LOG_ERROR << "SO_REUSEPORT is not supported.";
            }
#endif
        }


        class Timer : uncopyable {
        public:
            Timer(std::function<void()> cb, Timestamp when, double interval)
                : m_runtime(when), m_interval(interval), m_repeat(interval > 0.0), m_callback(std::move(cb)) {}

            void run() const { m_callback(); }
            void restart()
            {
                //如果是重复的定时器
                if (m_repeat)
                    m_runtime = Timestamp::AddTime(m_runtime, m_interval);  //重新计算下一个超时时刻
                else
                    m_runtime = Timestamp::invalid();
            }

            Timestamp GetRuntime() const { return m_runtime; }
            bool IsRepeat() const { return m_repeat; }



        private:
            Timestamp m_runtime;                     //超时的时刻(理想状态下回调函数运行的时刻)
            const double m_interval;                 //触发超时的间隔,为0则代表是一次性定时器
            const bool m_repeat;                     //是否重复
            const std::function<void()> m_callback;  //定时器回调函数
        };


        class Channel;
        class Poller;
        class TimerQueue;

    }  // namespace detail

    class TimerID : detail::copyable {
    public:
        explicit TimerID(detail::Timer* timer) : m_timer(timer) {}

    private:
        std::pair<Timestamp, detail::Timer*> Key() { return std::make_pair(m_timer->GetRuntime(), m_timer); }
        detail::Timer* m_timer;
        friend class detail::TimerQueue;
    };

    class EventLoop : detail::uncopyable {
    public:
        EventLoop();
        ~EventLoop();
        void loop();
        //可以跨线程调用，如果在其他线程调用，会调用wakeup保证退出
        void quit();
        Timestamp GetReturnTime() const { return m_returnTime; }
        int64_t GetLoopNum() const { return m_loopNum; }
        //在EventLoop所属的线程中执行此函数
        void run(std::function<void()> callback);
        //注册只执行一次的额外任务
        void AddExtraFunc(std::function<void()> callback);
        //某时刻触发Timer
        TimerID runAt(Timestamp time, std::function<void()> callback);
        //多久后触发Timer,单位second
        TimerID runAfter(double delay, std::function<void()> callback);
        //每隔多久触发Timer,单位second
        TimerID runEvery(double interval, std::function<void()> callback);
        //取消定时器
        void cancel(TimerID timerID);

        uint64_t GetExtraFuncsNum() const;
        //唤醒阻塞在poll的loop
        void wakeup();
        //注册channel到poller的map中
        void UpdateChannel(detail::Channel* channel);
        //从poller的map中移除channel
        void RemoveChannel(detail::Channel* channel);
        //m_poller中是否有channel
        bool HasChannel(detail::Channel* channel);
        pid_t GetThreadID() const { return m_threadID; }
        //断言此线程是相应的IO线程
        void AssertInLoopThread();
        //此线程是否是相应的IO线程
        bool InLoopThread() const { return m_threadID == this_thrd::tid(); }
        //是否正在调用回调函数
        bool IsRunningCallback() const { return m_runningCallback; }
        //获取此线程的EventLoop
        static EventLoop* GetLoopOfThisThread();

    private:
        void WakeUpRead();
        void RunExtraFunc();

        //DEBUG用的,打印每个事件
        void PrintActiveChannels() const;

        using ChannelList = std::vector<detail::Channel*>;

        bool m_looping = false;           //线程是否调用了loop()
        bool m_runningCallback = false;   //线程是否正在执行回调函数
        bool m_runningExtraFunc = false;  //  EventLoop线程是否正在执行的额外任务
        std::atomic_bool m_quit = false;  //线程是否调用了quit()
        int m_wakeUpfd;                   //一个eventfd   用于唤醒阻塞在poll的loop
        const pid_t m_threadID;
        detail::Channel* m_thisActiveChannel = nullptr;  //当前正在执行哪个channel的回调函数
        int64_t m_loopNum = 0;                           //loop总循环次数
        Timestamp m_returnTime;                          //有事件到来时返回的时间戳
        std::unique_ptr<detail::Poller> m_poller;
        std::unique_ptr<detail::TimerQueue> timerQueue_;   //Timer队列
        std::unique_ptr<detail::Channel> m_wakeUpChannel;  //用于唤醒后的回调函数
        ChannelList m_activeChannels;                      // 保存所有有事件到来的channel

        //EventLoop线程每次轮询除了执行有事件到来的channel的回调函数外，也会执行这个vector内的函数（额外的任务）
        std::vector<std::function<void()>> m_ExtraFuncs;
        mutable std::mutex m_mu;  //保护m_ExtraFuncs;
    };

    namespace detail {
        //当前线程EventLoop对象指针
        inline __thread EventLoop* t_loopOfThisThread = nullptr;

        inline const int k_PollTimeoutMs = 10000;

        inline int CreateEventfd()
        {
            if (int evtfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC); evtfd < 0)
            {
                LOG_SYSERR << "Failed in eventfd";
                abort();
            }
            else
                return evtfd;
        }

        inline void ReadTimerfd(int timerfd, Timestamp now)
        {
            uint64_t tmp;
            ssize_t n = read(timerfd, &tmp, sizeof(tmp));
            LOG_TRACE << "TimerQueue::ReadTimerfd() " << tmp << " at " << now.GmFormatString() << "(GM)";
            if (n != sizeof(tmp))
                LOG_ERROR << "TimerQueue::ReadTimerfd() reads " << n << " bytes instead of 8";
        }

        inline bool ignoreSigPipe = [] { return signal(SIGPIPE, SIG_IGN); }();
        inline bool setRandomSeed = [] { srand((uint32_t)time(0)); return 0; }();

        class EventLoopThread : uncopyable {
        public:
            EventLoopThread(const std::function<void(EventLoop*)>& threadInitCallback = std::function<void(EventLoop*)>(),
                            const std::string& name = std::string())
                : m_thrd(std::bind(&EventLoopThread::Loop, this), name), m_threadInitCallback(threadInitCallback) {}
            ~EventLoopThread();

            EventLoop* start();

        private:
            void Loop();

            EventLoop* m_loop = nullptr;
            bool m_exiting = false;
            Thread m_thrd;
            std::mutex m_mu;
            std::condition_variable m_cond;
            std::function<void(EventLoop*)> m_threadInitCallback;
        };

        class EventLoopThreadPool : uncopyable {
        public:
            EventLoopThreadPool(EventLoop* loop, const std::string& name);
            void SetThreadNum(int threadNum) { m_thrdNum = threadNum; }
            void start(const std::function<void(EventLoop*)>& threadInitCallback = std::function<void(EventLoop*)>());
            EventLoop* GetNextLoop();
            EventLoop* GetLoopRandom();
            std::vector<EventLoop*> GetAllLoops();
            bool started() const { return m_started; }
            const std::string& name() const { return m_name; }

        private:
            EventLoop* m_loop;
            std::string m_name;
            bool m_started = false;
            int m_thrdNum = 0;
            int m_next = 0;
            std::vector<std::unique_ptr<EventLoopThread>> m_thrds;
            std::vector<EventLoop*> m_loops;
        };

        class Channel : uncopyable {
        public:
            Channel(EventLoop* loop, int fd) : m_fd(fd), m_loop(loop) {}
            //处理事件
            void RunCallback(Timestamp timestamp);
            //设置可读事件回调函数
            void SetReadCallback(std::function<void(Timestamp)> callback) { m_readCallback = std::move(callback); }
            //设置可写事件回调函数
            void SetWriteCallback(std::function<void()> callback) { m_writeCallback = std::move(callback); }
            //设置关闭事件回调函数
            void SetCloseCallback(std::function<void()> callback) { m_closeCallback = std::move(callback); }
            //设置错误事件回调函数
            void SetErrorCallback(std::function<void()> callback) { m_errorCallback = std::move(callback); }

            //用于延长某些对象的生命期,使其寿命与obj相同
            void tie(const std::shared_ptr<void>&);
            int fd() const { return m_fd; }
            //返回注册的事件
            int GetEvents() const { return m_events; }
            //设置就绪的事件
            void SetRevents(int revents) { m_revents = revents; }

            //是否未注册事件
            bool IsNoneEvent() const { return m_events == k_NoneEvent; }

            //注册可读事件
            void OnReading();
            //注销读事件
            void OffReading();
            //注册写事件
            void OnWriting();
            //注销写事件
            void OffWriting();
            //注销所有事件
            void OffAll();
            //是否已注册可读事件
            bool IsReading() const { return m_events & k_ReadEvent; }
            //是否已注册写事件
            bool IsWriting() const { return m_events & k_WriteEvent; }
            //New=-1   Added=1   Deleted=2
            int GetStatus() { return m_status; }
            //New=-1   Added=1   Deleted=2
            void SetStatus(int status) { m_status = status; }

            //DEBUG 用
            std::string ReventsString() const { return EventsToString(m_fd, m_revents); }
            //DEBUG 用
            std::string EventsString() const { return EventsToString(m_fd, m_events); }

            //是否生成EPOLLHUP事件的日志
            void OnLogHup() { m_logHup = true; }
            //是否生成EPOLLHUP事件的日志
            void OffLogHup() { m_logHup = false; }
            //返回所属的EventLoop
            EventLoop* GetLoop() { return m_loop; }
            //暂时离开所属的EventLoop
            void remove();

        private:
            static std::string EventsToString(int fd, int ev);
            //加入所属的EventLoop
            void update();
            //处理到来的事件
            void RunCallbackWithGuard(Timestamp timestamp);

            static const int k_NoneEvent = 0;                   //无事件
            static const int k_ReadEvent = EPOLLIN | EPOLLPRI;  //可读
            static const int k_WriteEvent = EPOLLOUT;           //可写

            bool m_tied = false;             //  是否将生命周期绑定到了外部s
            bool m_runningCallback = false;  //是否处于处理事件中
            bool m_inLoop = false;           //是否已在EventLoop里注册
            bool m_logHup = true;            //EPOLLHUP时是否生成日志

            const int m_fd;     //此channel负责管理的文件描述符
            int m_events = 0;   //注册的事件
            int m_revents = 0;  //被poller设置的就绪的事件
            int m_status = -1;  //在poller中的状态
            EventLoop* m_loop;  //指向此channel所属的EventLoop

            std::weak_ptr<void> m_tie;                      //用来绑定obj以修改生命周期
            std::function<void(Timestamp)> m_readCallback;  //读事件回调函数
            std::function<void()> m_writeCallback;          //写事件回调函数
            std::function<void()> m_closeCallback;          //关闭事件回调函数
            std::function<void()> m_errorCallback;          //错误事件回调函数
        };

        class Poller : uncopyable {
        public:
            using ChannelList = std::vector<Channel*>;
            Poller(EventLoop* loop) : m_epollfd(epoll_create1(EPOLL_CLOEXEC)), m_loop(loop), m_events(k_InitEventListSize) {}
            ~Poller() = default;
            //对epoll_wait的封装,返回时间戳
            Timestamp poll(int timeoutMs, ChannelList* activeChannels);
            //添加channel
            void UpdateChannel(Channel* channel);
            //移除channel
            void RemoveChannel(Channel* channel);
            //这个channel是否在ChannelMap中
            bool HasChannel(Channel* channel) const;
            //断言此线程是相应的IO线程
            void AssertInLoopThread() const { m_loop->AssertInLoopThread(); }



        private:
            static const int k_New = -1;
            static const int k_Added = 1;
            static const int k_Deleted = 2;
            static const int k_InitEventListSize = 16;  //epoll事件表的大小

            static const char* OperationString(int operatoin);
            //将epoll返回的到来事件加到activeChannels里
            void CollectActiveChannels(int eventsNum, ChannelList* activeChannels) const;
            //注册事件,由operation决定
            void update(int operation, Channel* channel);

            using EventList = std::vector<epoll_event>;
            using ChannelMap = std::map<int, Channel*>;

            int m_epollfd;
            EventLoop* m_loop;      //指向所属的EventLoop
            EventList m_events;     //epoll事件数组
            ChannelMap m_channels;  //存储channel的map
        };

        class TimerQueue : uncopyable {
        private:
            using Key = std::pair<Timestamp, detail::Timer*>;
            using TimerMap = std::map<Key, std::unique_ptr<detail::Timer>>;
            using TimeoutTimer = std::vector<std::unique_ptr<detail::Timer>>;

        public:
            explicit TimerQueue(EventLoop* loop);
            ~TimerQueue();
            //可以跨线程调用
            TimerID add(std::function<void()> callback, Timestamp when, double interval);
            //可以跨线程调用
            void cancel(TimerID id) { m_loop->run(std::bind(&TimerQueue::CancelInLoop, this, id)); }

        private:
            //以下成员函数只可能在TimerQueue所属的IO线程调用，因而不用加锁

            void AddInLoop(detail::Timer* timer);
            void CancelInLoop(TimerID timerID);

            //当Timer触发超时时回调此函数
            void HandleTimerfd();
            //返回超时的Timer
            TimeoutTimer GetTimeout(Timestamp now);
            //重置非一次性的Timer
            void reset(TimeoutTimer& timeout);
            //向TimerMap中插入timer
            bool insert(detail::Timer* timer);

            bool runningCallback = false;
            const int m_timerfd;
            EventLoop* m_loop;                     //TimerQueue所属的EventLoop
            std::vector<TimerID> m_cancelledSoon;  //即将被cancel的timer
            TimerMap m_timers;
            Channel m_timerfdChannel;
        };

        class Acceptor : uncopyable {
        public:
            Acceptor(EventLoop* loop, const SockAddr& listenAddr, bool reuseport);
            ~Acceptor();
            void SetConnectionCallback(const std::function<void(int sockfd, const SockAddr&)>& cb) { m_ConnectionCallback = cb; }
            void listen();
            bool listening() const { return m_listening; }

        private:
            //处理事件
            void HandleRead();

            EventLoop* m_loop;
            detail::Socket m_sock;
            Channel m_channel;
            std::function<void(int sockfd, const SockAddr&)> m_ConnectionCallback;
            bool m_listening;
            int m_voidfd;  //空闲的fd,用于处理fd过多的情况
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




        inline EventLoopThread::~EventLoopThread()
        {
            m_exiting = true;
            if (m_loop != nullptr)
            {
                m_loop->quit();
                m_thrd.join();
            }
        }
        inline EventLoop* EventLoopThread::start()
        {
            m_thrd.start();
            std::unique_lock locker(m_mu);
            //如果初始化未完成
            if (m_loop == nullptr)
                m_cond.wait(locker, [this] { return m_loop != nullptr; });  //等待初始化完成
            return m_loop;
        }
        inline void EventLoopThread::Loop()
        {
            EventLoop loop;

            if (m_threadInitCallback)
                m_threadInitCallback(&loop);

            {
                std::lock_guard locker(m_mu);
                m_loop = &loop;
                m_cond.notify_one();
            }

            loop.loop();
            std::lock_guard locker(m_mu);
            m_loop = nullptr;
        }




        inline EventLoopThreadPool::EventLoopThreadPool(EventLoop* loop, const std::string& name)
            : m_loop(loop), m_name(name) {}
        inline void EventLoopThreadPool::start(const std::function<void(EventLoop*)>& threadInitCallback)
        {
            m_loop->AssertInLoopThread();
            m_started = true;
            //创建m_thrdNum个线程，每个线程都用threadInitCallback进行初始化
            for (int i = 0; i < m_thrdNum; i++)
            {
                char name[m_name.size() + 32];
                fmt::format_to(name, "{}{}", m_name.c_str(), i);
                EventLoopThread* p = new EventLoopThread(threadInitCallback, name);
                m_thrds.emplace_back(std::unique_ptr<EventLoopThread>(p));
                m_loops.emplace_back(p->start());
            }
            //如果m_thrdNum == 0,就用当前线程执行threadInitCallback
            if (m_thrdNum == 0 && threadInitCallback)
                threadInitCallback(m_loop);
        }
        inline EventLoop* EventLoopThreadPool::GetNextLoop()
        {
            m_loop->AssertInLoopThread();
            EventLoop* loop = m_loop;

            if (!m_loops.empty())
            {
                loop = m_loops[m_next++];
                if ((uint64_t)m_next >= m_loops.size())
                    m_next = 0;
            }
            return loop;
        }
        inline EventLoop* EventLoopThreadPool::GetLoopRandom()
        {
            m_loop->AssertInLoopThread();
            if (!m_loops.empty())
                return m_loops[rand() % m_loops.size()];
        }
        inline std::vector<EventLoop*> EventLoopThreadPool::GetAllLoops()
        {
            m_loop->AssertInLoopThread();
            if (m_loops.empty())
                return std::vector<EventLoop*>(1, m_loop);  //没有就造一个
            else
                return m_loops;
        }




        inline void Channel::RunCallback(Timestamp timestamp)
        {
            std::shared_ptr<void> guard;
            if (m_tied)
            {
                if (guard = m_tie.lock(); guard)  //如果绑定的对象还活着
                    RunCallbackWithGuard(timestamp);
            }
            else
                RunCallbackWithGuard(timestamp);
        }
        inline void Channel::tie(const std::shared_ptr<void>& obj)
        {
            m_tie = obj;
            m_tied = true;
        }
        inline void Channel::remove()
        {
            m_inLoop = false;
            m_loop->RemoveChannel(this);
        }
        inline std::string Channel::EventsToString(int fd, int ev)
        {
            std::string str = fmt::format("{}: ", fd);
            str.reserve(32);
            if (ev & EPOLLIN)
                str += "IN ";
            if (ev & EPOLLPRI)
                str += "PRI ";
            if (ev & EPOLLOUT)
                str += "OUT ";
            if (ev & EPOLLHUP)
                str += "HUP ";
            if (ev & EPOLLRDHUP)
                str += "RDHUP ";
            if (ev & EPOLLERR)
                str += "ERR ";

            return str;
        }
        inline void Channel::update()
        {
            m_inLoop = true;
            m_loop->UpdateChannel(this);
        }
        inline void Channel::RunCallbackWithGuard(Timestamp timestamp)
        {
            m_runningCallback = true;
            LOG_TRACE << ReventsString();
            if ((m_revents & EPOLLHUP) && !(m_revents & EPOLLIN))  //客户端主动关闭(调用close)
            {
                if (m_logHup)
                    LOG_WARN << "fd = " << m_fd << " Channel::RunCallbackWithGuard() EPOLLHUP";
                if (m_closeCallback)
                    m_closeCallback();
            }
            if (m_revents & EPOLLERR)
            {
                if (m_errorCallback)
                    m_errorCallback();
            }
            if (m_revents & (EPOLLIN | EPOLLPRI | EPOLLRDHUP))
            {
                if (m_readCallback)
                    m_readCallback(timestamp);
            }
            if (m_revents & EPOLLOUT)
            {
                if (m_writeCallback)
                    m_writeCallback();
            }
            m_runningCallback = false;
        }
        inline void Channel::OnReading()
        {
            m_events |= k_ReadEvent;
            update();
        }
        inline void Channel::OffReading()
        {
            m_events &= ~k_ReadEvent;
            update();
        }
        inline void Channel::OnWriting()
        {
            m_events |= k_WriteEvent;
            update();
        }
        inline void Channel::OffWriting()
        {
            m_events &= ~k_WriteEvent;
            update();
        }
        inline void Channel::OffAll()
        {
            m_events = k_NoneEvent;
            update();
        }



        inline Timestamp Poller::poll(int timeoutMs, ChannelList* activeChannels)
        {
            LOG_TRACE << "fd total count " << m_channels.size();
            int numEvents = epoll_wait(m_epollfd, &*m_events.begin(), (int)m_events.size(), timeoutMs);
            int tmpErrno = errno;
            Timestamp now;
            if (numEvents > 0)
            {
                LOG_TRACE << numEvents << " events happened";
                CollectActiveChannels(numEvents, activeChannels);
                if ((uint64_t)numEvents == m_events.size())
                    m_events.resize(m_events.size() * 2);  //说明m_events的大小要不够用了，扩容
            }
            else if (numEvents == 0)
            {
                LOG_TRACE << "nothing happened";
            }
            else if (tmpErrno != EINTR)
            {
                errno = tmpErrno;
                LOG_SYSERR << "Poller::poll()";
            }
            return now;
        }
        inline void Poller::UpdateChannel(Channel* channel)
        {
            Poller::AssertInLoopThread();
            const int status = channel->GetStatus();
            LOG_TRACE << "fd = " << channel->fd()
                      << " events = " << channel->GetEvents() << " index = " << status;
            if (status == k_New || status == k_Deleted)  //新的或之前被移出epoll但没有从ChannelMap里删除的
            {
                int fd = channel->fd();
                if (status == k_New)           //如果是新的
                    m_channels[fd] = channel;  //在ChannelMap里注册

                //旧的就不用注册到ChannelMap里了
                channel->SetStatus(k_Added);     //设置状态为已添加
                update(EPOLL_CTL_ADD, channel);  //将channel对应的fd注册到epoll中
            }
            else  //修改
            {
                if (channel->IsNoneEvent())  //此channel是否未注册事件
                {
                    update(EPOLL_CTL_DEL, channel);  //直接从epoll中删除
                    channel->SetStatus(k_Deleted);   //只代表不在epoll中，不代表已经从ChannelMap中移除
                }
                else
                    update(EPOLL_CTL_MOD, channel);  //修改(更新)事件
            }
        }
        inline bool Poller::HasChannel(Channel* channel) const
        {
            AssertInLoopThread();
            auto it = m_channels.find(channel->fd());
            return it != m_channels.end() && it->second == channel;
        }
        inline void Poller::RemoveChannel(Channel* channel)
        {
            Poller::AssertInLoopThread();
            int fd = channel->fd();
            LOG_TRACE << "fd = " << fd;
            int status = channel->GetStatus();
            m_channels.erase(fd);  //从ChannelMap中移除

            if (status == k_Added)               //如果已在epoll中注册
                update(EPOLL_CTL_DEL, channel);  //就从epoll中移除
            channel->SetStatus(k_New);
        }
        inline const char* Poller::OperationString(int operatoin)
        {
            switch (operatoin)
            {
                case EPOLL_CTL_ADD:
                    return "ADD";
                case EPOLL_CTL_DEL:
                    return "DEL";
                case EPOLL_CTL_MOD:
                    return "MOD";
                default:
                    return "Unknown Operation";
            }
        }
        inline void Poller::CollectActiveChannels(int eventsNum, ChannelList* activeChannels) const
        {
            for (int i = 0; i < eventsNum; ++i)
            {
                Channel* channel = (Channel*)m_events[i].data.ptr;
                channel->SetRevents(m_events[i].events);
                activeChannels->emplace_back(channel);
            }
        }
        inline void Poller::update(int operation, Channel* channel)
        {
            epoll_event event;
            memset(&event, 0, sizeof(event));
            event.events = channel->GetEvents();
            event.data.ptr = channel;  //这一步使得在epoll_wait返回时能通过data.ptr访问对应的channel
            int fd = channel->fd();
            LOG_TRACE << "epoll_ctl op = " << OperationString(operation)
                      << " fd = " << fd << " event = { " << channel->EventsString() << " }";

            if (epoll_ctl(m_epollfd, operation, fd, &event) < 0)  //将fd注册到epoll中
            {
                if (operation == EPOLL_CTL_DEL)
                    LOG_SYSERR << "epoll_ctl op =" << OperationString(operation) << " fd =" << fd;
                else
                    LOG_SYSFATAL << "epoll_ctl op =" << OperationString(operation) << " fd =" << fd;
            }
        }



        inline TimerQueue::TimerQueue(EventLoop* loop)
            : m_timerfd(detail::MakeNonblockingTimerfd()), m_loop(loop), m_timerfdChannel(loop, m_timerfd)
        {
            m_timerfdChannel.SetReadCallback(std::bind(&TimerQueue::HandleTimerfd, this));
            m_timerfdChannel.OnReading();
        }
        inline TimerQueue::~TimerQueue()
        {
            m_timerfdChannel.OffAll();
            m_timerfdChannel.remove();
            detail::Close(m_timerfd);
        }
        inline TimerID TimerQueue::add(std::function<void()> callback, Timestamp when, double interval)
        {
            detail::Timer* timer = new detail::Timer(std::move(callback), when, interval);
            //在IO线程中执行addTimerInLoop,保证线程安全
            m_loop->run(std::bind(&TimerQueue::AddInLoop, this, timer));

            return TimerID(timer);
        }
        inline void TimerQueue::AddInLoop(detail::Timer* timer)
        {
            m_loop->AssertInLoopThread();
            //插入一个Timer，有可能会使得最早到期的时间发生改变
            bool earliestChanged = insert(timer);
            //如果发生改变，就要重置最早到期的时间
            if (earliestChanged)
                detail::ResetTimerfd(m_timerfd, timer->GetRuntime());
        }
        inline void TimerQueue::CancelInLoop(TimerID id)
        {
            m_loop->AssertInLoopThread();

            if (auto p = m_timers.find(id.Key()); p != m_timers.end())
            {
                if (!runningCallback)
                    m_timers.erase(p);
                else
                    m_cancelledSoon.emplace_back(p->second.get());
            }
        }
        inline void TimerQueue::HandleTimerfd()
        {
            m_loop->AssertInLoopThread();
            Timestamp now;
            detail::ReadTimerfd(m_timerfd, now);  //清理超时事件，避免一直触发  //FIXME  LT模式的弊端?

            //获取now之前的所有Timer
            TimeoutTimer timeout = GetTimeout(now);

            runningCallback = true;
            //调用超时Timer的回调函数
            for (auto&& item : timeout)
                item->run();
            runningCallback = false;

            //重置非一次性的Timer
            reset(timeout);
        }
        inline TimerQueue::TimeoutTimer TimerQueue::GetTimeout(Timestamp now)
        {
            //返回第一个未到期的Timer的迭代器，即这个迭代器之前的所有Timer都已经到期了
            auto end = m_timers.lower_bound(Key(now, (detail::Timer*)UINTPTR_MAX));
            auto p = m_timers.begin();
            TimeoutTimer timeout;
            timeout.reserve(std::distance(p, end));

            while (p != end)
            {
                timeout.emplace_back(std::move(p->second));
                m_timers.erase(p++);
            }
            return timeout;
        }
        inline void TimerQueue::reset(TimeoutTimer& timeout)
        {
            for (auto&& item : timeout)
                if (item->IsRepeat())
                {
                    item->restart();
                    m_timers[std::make_pair(item->GetRuntime(), item.get())] = std::move(item);
                }

            for (auto&& it : m_cancelledSoon)
                m_timers.erase(it.Key());
            m_cancelledSoon.clear();

            while (!m_timers.empty())
                if (detail::ResetTimerfd(m_timerfd, m_timers.begin()->second->GetRuntime()) == 0)
                    break;
                else
                {
                    LOG_ERROR << "a timeout timer was ignored";
                    std::unique_ptr<detail::Timer>& timer = m_timers.begin()->second;
                    if (timer->IsRepeat())
                    {
                        timer->restart();
                        m_timers[std::make_pair(timer->GetRuntime(), timer.get())] = std::move(timer);
                    }
                    m_timers.erase(m_timers.begin());
                }
        }
        inline bool TimerQueue::insert(detail::Timer* timer)
        {
            bool earliestChanged = false;
            Timestamp when = timer->GetRuntime();  //取出timer的到期时间

            //如果set为空或此timer比set中最早的timer还早
            if (m_timers.empty() || when < m_timers.begin()->first.first)
                earliestChanged = true;  //就需要修改超时时间

            m_timers[std::make_pair(when, timer)] = std::unique_ptr<detail::Timer>(timer);
            return earliestChanged;
        }



        inline Acceptor::Acceptor(EventLoop* loop, const SockAddr& listenAddr, bool reuseport)
            : m_loop(loop),
              m_sock(detail::MakeNonblockingSocket(listenAddr.famliy())),
              m_channel(loop, m_sock.fd()),
              m_listening(false),
              m_voidfd(open("/dev/null", O_RDONLY | O_CLOEXEC))  //预先准备一个空闲的fd
        {
            m_sock.SetReuseAddr(true);  //设置SO_REUSEADDR,如果这个端口处于TIME_WAIT,也可bind成功

            m_sock.SetReusePort(reuseport);  //  设置SO_REUSEPORT,作用是支持多个进程或线程绑定到同一端口
                                             // 内核会采用负载均衡的的方式分配客户端的连接请求给某一个进程或线程

            m_sock.bind((SockAddr*)&listenAddr);
            m_channel.SetReadCallback(std::bind(&Acceptor::HandleRead, this));
        }
        inline Acceptor::~Acceptor()
        {
            m_channel.OffAll();
            m_channel.remove();
            detail::Close(m_voidfd);
        }
        inline void Acceptor::listen()
        {
            m_loop->AssertInLoopThread();
            m_listening = true;
            m_sock.listen();
            m_channel.OnReading();
        }
        inline void Acceptor::HandleRead()
        {
            m_loop->AssertInLoopThread();
            SockAddr peerAddr;

            if (int connfd = m_sock.accept(&peerAddr); connfd >= 0)
            {
                if (m_ConnectionCallback)
                    m_ConnectionCallback(connfd, peerAddr);
                else
                    detail::Close(connfd);
            }
            else  //FIXME  因为epoll不是ET模式，需要这样来防止因fd过多处理不了而导致epoll繁忙
            {
                LOG_SYSERR << "in Acceptor::handleRead";
                if (errno == EMFILE)  //打开了过多了fd,超过了允许的范围
                {
                    detail::Close(m_voidfd);
                    m_voidfd = accept(m_sock.fd(), NULL, NULL);
                    detail::Close(m_voidfd);
                    m_voidfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
                }
            }
        }

    }  // namespace detail

    class Buffer : detail::copyable {
    public:
        static const uint64_t k_PrependSize = 8;
        static const uint64_t k_InitSize = 1024;

        explicit Buffer(uint64_t initialSize = k_InitSize)
            : m_vec(k_PrependSize + initialSize), m_readIndex(k_PrependSize), m_writeIndex(k_PrependSize) {}

        void swap(Buffer& other);

        uint64_t ReadableBytes() const { return m_writeIndex - m_readIndex; }
        uint64_t WritableBytes() const { return m_vec.size() - m_writeIndex; }
        uint64_t PrependableBytes() const { return m_readIndex; }


        const char* FindCRLF() const;
        const char* FindCRLF(const char* start) const;
        const char* FindEOL() const { return (const char*)memchr(BeginRead(), '\n', ReadableBytes()); }
        const char* FindEOL(const char* start) const { return (const char*)memchr(start, '\n', BeginWrite() - start); }

        void drop(uint64_t len);
        void DropUntil(const char* end) { drop(end - BeginRead()); }
        void DropInt64() { drop(sizeof(int64_t)); }
        void DropInt32() { drop(sizeof(int)); }
        void DropInt16() { drop(sizeof(int16_t)); }
        void DropInt8() { drop(sizeof(int8_t)); }
        void DropAll();

        std::string RetrieveAllAsString() { return RetrieveAsString(ReadableBytes()); }
        std::string RetrieveAsString(uint64_t len);

        std::string_view ToStringView() const { return std::string_view(BeginRead(), ReadableBytes()); }
        std::string ToString() const { return std::string(BeginRead(), ReadableBytes()); }

        void append(const char* data, uint64_t len);
        void append(const void* data, uint64_t len) { append((const char*)data, len); }
        void append(const std::string_view& str) { append(str.data(), str.size()); }
        void AppendInt64(int64_t x);
        void AppendInt32(int x);
        void AppendInt16(int16_t x);
        void AppendInt8(int8_t x) { append(&x, sizeof(x)); }

        const char* BeginRead() const { return begin() + m_readIndex; }
        char* BeginWrite() { return begin() + m_writeIndex; }
        const char* BeginWrite() const { return begin() + m_writeIndex; }

        int64_t ReadInt64();
        int ReadInt32();
        int16_t ReadInt16();
        int8_t ReadInt8();

        int64_t PeekInt64() const;
        int PeekInt32() const;
        int16_t PeekInt16() const;
        int8_t PeekInt8() const { return *BeginRead(); }

        void PrependInt64(int64_t x);
        void PrependInt32(int x);
        void PrependInt16(int16_t x);
        void PrependInt8(int8_t x) { prepend(&x, sizeof(x)); }

        void shrink(uint64_t reserve);

        uint64_t capacity() const { return m_vec.capacity(); }

        ssize_t Read(int fd, int* savedErrno);

    private:
        void prepend(const void* data, uint64_t len);
        void EnsureWritableBytes(uint64_t len);
        void WriteIndexRightShift(uint64_t len) { m_writeIndex += len; }
        void WriteIndexLeftShift(uint64_t len) { m_writeIndex -= len; }
        char* begin() { return &*m_vec.begin(); }
        const char* begin() const { return &*m_vec.begin(); }
        void MakeSpace(uint64_t len);

    private:
        std::vector<char> m_vec;
        uint64_t m_readIndex;   //从这里开始读
        uint64_t m_writeIndex;  //从这里开始写

        static const char k_CRLF[];
    };
    inline const char Buffer::k_CRLF[] = "\r\n";

    class TcpConnection : detail::uncopyable, public std::enable_shared_from_this<TcpConnection> {
    public:
        TcpConnection(EventLoop* loop, const std::string& name, int sockfd, const SockAddr& localAddr, const SockAddr& peerAddr);
        ~TcpConnection();
        //获取所在的EventLoop
        EventLoop* GetLoop() const { return m_loop; }
        //获取名称
        const std::string& name() const { return m_name; }
        //本地地址
        const SockAddr& LocalAddr() const { return m_localAddr; }
        //远端地址
        const SockAddr& PeerAddr() const { return m_peerAddr; }
        //是否已连接
        bool connected() const { return m_status == k_Connected; }
        //是否已断开连接
        bool disconnected() const { return m_status == k_Disconnected; }
        // return true if success.
        bool GetTcpInfo(struct tcp_info* tcpi) const { return m_socket->GetTcpInfo(tcpi); }
        std::string GetTcpInfoString() const;

        void send(std::string&& msg);  // C++11
        void send(const void* data, int len) { send(std::string_view((const char*)data, len)); }
        void send(const std::string_view& msg);
        void send(Buffer* buf);
        //线程不安全,不能跨线程调用
        void shutdown();

        void ForceClose();
        void ForceCloseWithDelay(double seconds);
        //设置TcpNoDelay
        void SetTcpNoDelay(bool on);

        void startRead() { m_loop->run(std::bind(&TcpConnection::StartReadInLoop, this)); }
        void stopRead() { m_loop->run(std::bind(&TcpConnection::StopReadInLoop, this)); }
        //线程不安全
        bool isReading() const { return m_reading; }
        //连接建立 销毁 产生关闭事件时 都会调用这个回调函数
        void setConnectionCallback(const std::function<void(const std::shared_ptr<TcpConnection>&)>& callback) { m_connCallback = callback; }
        //接收到数据之后会调用这个回调函数
        void setMessageCallback(const std::function<void(const std::shared_ptr<TcpConnection>&, Buffer*, Timestamp)>& callback)
        {
            m_msgCallback = callback;
        }
        //写操作完成时会调用这个回调函数
        void setWriteCompleteCallback(const std::function<void(const std::shared_ptr<TcpConnection>&)>& callback)
        {
            m_writeDoneCallback = callback;
        }
        //应用层缓冲区堆积的数据大于m_highWaterMark时调用
        void setHighWaterMarkCallback(const std::function<void(const std::shared_ptr<TcpConnection>&, uint64_t)>& callback, uint64_t highWaterMark)
        {
            m_highWaterMarkCallback = callback;
            m_highWaterMark = highWaterMark;
        }

        Buffer* inputBuffer() { return &m_inputBuf; }
        Buffer* outputBuffer() { return &m_outputBuf; }

        void setCloseCallback(const std::function<void(const std::shared_ptr<TcpConnection>&)>& callback)
        {
            m_closeCallback = callback;
        }

        //当TcpServer accept一个连接时会调用这个函数
        void ConnectEstablished();
        //当TcpServer remove一个连接或自身析构时会调用这个函数
        void ConnectDestroyed();

    private:
        void handleRead(Timestamp receiveTime);
        void handleWrite();
        void handleClose();
        void handleError();
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

        EventLoop* m_loop;         //所属的EventLoop
        uint64_t m_highWaterMark;  //应用层缓冲区堆积的数据大于这个数(byte)就回调m_highWaterMarkCallback
        const std::string m_name;  //名称
        std::atomic_int m_status;  //连接的状态
        bool m_reading;            //是否正在read
        std::unique_ptr<detail::Socket> m_socket;
        std::unique_ptr<detail::Channel> m_channel;
        const SockAddr m_localAddr;  //本地地址
        const SockAddr m_peerAddr;   //对端地址
        std::function<void(const std::shared_ptr<TcpConnection>&)> m_connCallback;
        std::function<void(const std::shared_ptr<TcpConnection>&, Buffer*, Timestamp)> m_msgCallback;
        std::function<void(const std::shared_ptr<TcpConnection>&)> m_writeDoneCallback;
        std::function<void(const std::shared_ptr<TcpConnection>&, uint64_t)> m_highWaterMarkCallback;
        std::function<void(const std::shared_ptr<TcpConnection>&)> m_closeCallback;
        Buffer m_inputBuf;
        Buffer m_outputBuf;
    };

    class TcpServer : detail::uncopyable {
    public:
        using ThreadInitCallback = std::function<void(EventLoop*)>;
        enum Option {
            kNoReusePort,
            kReusePort,
        };

        TcpServer(EventLoop* loop, const SockAddr& listenAddr, const std::string& name, Option option = kNoReusePort);
        ~TcpServer();

        const std::string& ipPort() const { return m_ipPort; }
        const std::string& name() const { return m_name; }
        EventLoop* getLoop() const { return m_loop; }
        //必须在start之前调用
        void setThreadNum(int numThreads) { m_threadPool->SetThreadNum(numThreads); }
        //必须在start之前调用
        void setThreadInitCallback(const ThreadInitCallback& callback) { m_threadInitCallback = callback; }
        // 必须在start之后调用
        std::shared_ptr<detail::EventLoopThreadPool> threadPool() { return m_threadPool; }

        //启动,线程安全
        void start();
        //连接到来或连接关闭时回调的函数,线程不安全
        void setConnectionCallback(const std::function<void(const std::shared_ptr<TcpConnection>&)>& callback)
        {
            m_connCallback = callback;
        }
        //消息到来时回调的函数,线程不安全
        void setMessageCallback(const std::function<void(const std::shared_ptr<TcpConnection>&, Buffer*, Timestamp)>& callback)
        {
            m_msgCallback = callback;
        }
        //write完成时会回调的函数,线程不安全
        void setWriteCompleteCallback(const std::function<void(const std::shared_ptr<TcpConnection>&)>& callback)
        {
            m_writeDoneCallback = callback;
        }

    private:
        using ConnectionMap = std::map<std::string, std::shared_ptr<TcpConnection>>;
        //连接到来时会回调的函数
        void newConnection(int sockfd, const SockAddr& peerAddr);
        //将这个TcpConnection从map中删除,线程安全
        void removeConnection(const std::shared_ptr<TcpConnection>& conn);
        //将这个TcpConnection从map中删除
        void removeConnectionInLoop(const std::shared_ptr<TcpConnection>& conn);

    private:
        std::atomic_bool m_started = false;
        int m_nextConnID;
        std::unique_ptr<detail::Acceptor> m_acceptor;
        EventLoop* m_loop;  // TcpServer所属的EventLoop
        std::shared_ptr<detail::EventLoopThreadPool> m_threadPool;
        const std::string m_ipPort;
        const std::string m_name;
        std::function<void(const std::shared_ptr<TcpConnection>&)> m_connCallback;                     //连接到来执行的回调函数
        std::function<void(const std::shared_ptr<TcpConnection>&, Buffer*, Timestamp)> m_msgCallback;  //消息到来执行的回调函数
        std::function<void(const std::shared_ptr<TcpConnection>&)> m_writeDoneCallback;                //写操作完成时执行的回调函数
        std::function<void(EventLoop*)> m_threadInitCallback;
        ConnectionMap m_connections;
    };

    namespace detail {
        void DefaultConnCallback(const std::shared_ptr<kurisu::TcpConnection>& conn)
        {
            LOG_TRACE << conn->LocalAddr().ipPortString() << " -> "
                      << conn->PeerAddr().ipPortString() << " is "
                      << (conn->connected() ? "Connected" : "Disconnected");
        }
        void DefaultMsgCallback(const std::shared_ptr<kurisu::TcpConnection>&, kurisu::Buffer* buf, kurisu::Timestamp)
        {
            buf->DropAll();
        }
    }  // namespace detail








    inline char* Timestamp::GmLogFormat(char* buf) const
    {
        uint64_t us = usSinceEpoch() - secondsSinceEpoch() * 1'000'000;
        return fmt::format_to(buf, FMT_COMPILE("[{:%F %T}.{:06}] "), fmt::gmtime(m_stamp), us);
    }
    inline char* Timestamp::LocalLogFormat(char* buf) const
    {
        uint64_t us = usSinceEpoch() - secondsSinceEpoch() * 1'000'000;
        return fmt::format_to(buf, FMT_COMPILE("[{:%F %T}.{:06}] "), fmt::localtime(m_stamp), us);
    }
    inline int64_t Timestamp::usSinceEpoch() const
    {
        using namespace std::chrono;
        return duration_cast<microseconds>(m_stamp.time_since_epoch()).count();
    }
    inline int64_t Timestamp::nsSinceEpoch() const
    {
        using namespace std::chrono;
        return duration_cast<nanoseconds>(m_stamp.time_since_epoch()).count();
    }
    inline int64_t Timestamp::secondsSinceEpoch() const
    {
        using namespace std::chrono;
        return duration_cast<seconds>(m_stamp.time_since_epoch()).count();
    }
    inline double Timestamp::TimeDifference(Timestamp high, Timestamp low)
    {
        using namespace std::chrono;
        auto a = duration_cast<microseconds>(high.GetStamp().time_since_epoch()).count();
        auto b = duration_cast<microseconds>(low.GetStamp().time_since_epoch()).count();
        return (double)(a - b) / 1'000'000;
    }
    inline Timestamp Timestamp::AddTime(Timestamp stamp, double second)
    {
        using namespace std::chrono;
        uint64_t s = (uint64_t)second;
        uint64_t us = (uint64_t)((second - (double)s) * 1'000'000);
        return Timestamp(stamp.GetStamp() + seconds(s) + microseconds(us));
    }




    inline Logger::Formatter::Formatter(LogLevel level, int savedErrno, std::string_view file, int line)
        : m_time(Timestamp::now()), m_strm(), m_level(level), m_line(line)
    {
        if (auto slash = file.rfind('/'); slash != std::string_view::npos)
        {
            file = file.substr(slash + 1);
            m_fileName = file.data();
        }
        m_fileNameSize = file.size();

        FormatTime();
        this_thrd::tid();
        m_strm << '[' << detail::KnownLengthString(this_thrd::TidString(), this_thrd::TidStringLength()) << ']' << " ";
        m_strm << detail::KnownLengthString(detail::LogLevelName[(int)level], 8);
        if (savedErrno != 0)
            m_strm << detail::strerror_tl(savedErrno) << " (errno=" << savedErrno << ") ";
    }
    inline void Logger::Formatter::FormatTime()
    {
        using namespace detail;
        static KnownLengthString timeString(t_time, 0);
        char* p = nullptr;

        if (m_time.secondsSinceEpoch() != t_lastSecond)
        {
            t_lastSecond = m_time.secondsSinceEpoch();
            if (!s_isLocalTimeZone)
                p = m_time.GmLogFormat(t_time);
            else
                p = m_time.LocalLogFormat(t_time);
        }

        if (p)
            timeString = KnownLengthString(t_time, p - t_time);

        m_strm << timeString;
    }
    inline void Logger::Formatter::finish()
    {
        m_strm << " - " << detail::KnownLengthString(m_fileName, m_fileNameSize) << ':' << m_line << '\n';
    }
    inline Logger::Logger(const std::string_view& file, int line) : m_fmt(LogLevel::INFO, 0, file, line) {}
    inline Logger::Logger(const std::string_view& file, int line, LogLevel level, const char* func)
        : m_fmt(level, 0, file, line) { m_fmt.m_strm << func << ' '; }
    inline Logger::Logger(const std::string_view& file, int line, LogLevel level) : m_fmt(level, 0, file, line) {}
    inline Logger::Logger(const std::string_view& file, int line, bool toAbort)
        : m_fmt(toAbort ? LogLevel::FATAL : LogLevel::ERROR, errno, file, line) {}
    inline Logger::~Logger()
    {
        using namespace std::chrono;
        m_fmt.finish();

        const detail::LogStream::Buf& buf(stream().buffer());

        detail::g_output(buf.data(), buf.size());

        if (m_fmt.m_level == LogLevel::FATAL)
        {
            detail::g_flush();
            abort();
        }
    }
    inline Logger::LogLevel Logger::level() { return detail::g_logLevel; }
    inline void Logger::SetOutput(void (*out)(const char* msg, const uint64_t len)) { detail::g_output = out; }
    inline void Logger::SetFlush(void (*flush)()) { detail::g_flush = flush; }
    class Logger::SetLogLevel {
    public:
        static void TRACE() { detail::g_logLevel = Logger::LogLevel::TRACE; }
        static void DEBUG() { detail::g_logLevel = Logger::LogLevel::DEBUG; }
        static void INFO() { detail::g_logLevel = Logger::LogLevel::INFO; }
        static void WARN() { detail::g_logLevel = Logger::LogLevel::WARN; }
        static void ERROR() { detail::g_logLevel = Logger::LogLevel::ERROR; }
        static void FATAL() { detail::g_logLevel = Logger::LogLevel::FATAL; }
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



    inline AsyncLogFile::AsyncLogFile(const std::string& basename, int64_t rollSize, bool localTimeZone, int flushInterval)
        : k_flushInterval(flushInterval),
          m_isLocalTimeZone(localTimeZone),
          m_fileName(basename),
          m_rollSize(rollSize),
          m_thrd(std::bind(&AsyncLogFile::Loop, this), "Async Logger"),
          m_thisBuf(std::make_unique<Buf>()),
          m_nextBuf(std::make_unique<Buf>())
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



    inline SockAddr::SockAddr(uint16_t port, const char* host) { detail::IpProtToAddr(port, host, this); }
    inline std::string SockAddr::ipString() const
    {
        char buf[64] = {0};
        detail::AddrToIp(buf, 64, (SockAddr*)this);
        return buf;
    }
    inline std::string SockAddr::ipPortString() const
    {
        char buf[64] = {0};
        detail::AddrToIpPort(buf, 64, (SockAddr*)this);
        return buf;
    }
    inline uint16_t SockAddr::HostPort() const
    {
        if (famliy() == AF_INET)
            return ntohs(sin.sin_port);
        else
            return ntohs(sin6.sin6_port);
    }
    inline uint16_t SockAddr::NetPort() const
    {
        if (famliy() == AF_INET)
            return sin.sin_port;
        else
            return sin6.sin6_port;
    }



    EventLoop::EventLoop()
        : m_wakeUpfd(detail::CreateEventfd()),
          m_threadID(this_thrd::tid()),
          m_poller(std::make_unique<detail::Poller>(this)),
          timerQueue_(std::make_unique<detail::TimerQueue>(this)),
          m_wakeUpChannel(std::make_unique<detail::Channel>(this, m_wakeUpfd))
    {
        LOG_DEBUG << "EventLoop created " << this << " in thread " << m_threadID;
        if (detail::t_loopOfThisThread)
            LOG_FATAL << "Another EventLoop " << detail::t_loopOfThisThread << " exists in this thread " << m_threadID;
        else
            detail::t_loopOfThisThread = this;
        m_wakeUpChannel->SetReadCallback(std::bind(&EventLoop::WakeUpRead, this));  //以便调用quit时唤醒loop
        m_wakeUpChannel->OnReading();
    }
    inline EventLoop::~EventLoop()
    {
        LOG_DEBUG << "EventLoop " << this << " of thread " << m_threadID
                  << " destructs in thread " << this_thrd::tid();
        m_wakeUpChannel->OffAll();
        m_wakeUpChannel->remove();
        detail::Close(m_wakeUpfd);
        detail::t_loopOfThisThread = nullptr;
    }
    inline void EventLoop::loop()
    {
        AssertInLoopThread();
        m_looping = true;
        m_quit = false;
        LOG_TRACE << "EventLoop " << this << " start looping";

        while (!m_quit)
        {
            m_activeChannels.clear();  //删除所有active channel

            //没事的时候loop会阻塞在这里
            m_returnTime = m_poller->poll(detail::k_PollTimeoutMs, &m_activeChannels);
            ++m_loopNum;

            if (Logger::level() <= Logger::LogLevel::TRACE)
                PrintActiveChannels();  //将发生的事件写入日志

            m_runningCallback = true;
            //执行每个有事件到来的channel的回调函数
            for (auto&& channel : m_activeChannels)
                channel->RunCallback(m_returnTime);

            m_thisActiveChannel = nullptr;
            m_runningCallback = false;
            RunExtraFunc();  //执行额外的回调函数
        }

        LOG_TRACE << "EventLoop " << this << " stop looping";
        m_looping = false;
    }
    inline void EventLoop::quit()
    {
        m_quit = true;
        if (!InLoopThread())
            wakeup();
    }
    inline void EventLoop::run(std::function<void()> callback)
    {
        if (InLoopThread())
            callback();
        else
            AddExtraFunc(std::move(callback));
    }
    inline void EventLoop::AddExtraFunc(std::function<void()> callback)
    {
        {
            std::lock_guard lock(m_mu);
            m_ExtraFuncs.emplace_back(std::move(callback));
        }

        if (!InLoopThread() || m_runningExtraFunc)
            wakeup();
    }
    inline uint64_t EventLoop::GetExtraFuncsNum() const
    {
        std::lock_guard lock(m_mu);
        return m_ExtraFuncs.size();
    }
    inline void EventLoop::wakeup()
    {
        uint64_t one = 1;
        ssize_t n = detail::Write(m_wakeUpfd, &one, sizeof(one));
        if (n != sizeof(one))
            LOG_ERROR << "EventLoop::wakeup() writes " << n << " bytes instead of 8";
    }
    inline void EventLoop::UpdateChannel(detail::Channel* channel)
    {
        AssertInLoopThread();
        m_poller->UpdateChannel(channel);
    }
    inline void EventLoop::RemoveChannel(detail::Channel* channel)
    {
        AssertInLoopThread();
        m_poller->RemoveChannel(channel);
    }
    inline bool EventLoop::HasChannel(detail::Channel* channel)
    {
        AssertInLoopThread();
        return m_poller->HasChannel(channel);
    }
    inline EventLoop* EventLoop::GetLoopOfThisThread() { return detail::t_loopOfThisThread; }
    inline void EventLoop::WakeUpRead()
    {
        uint64_t one = 1;
        ssize_t n = detail::Read(m_wakeUpfd, &one, sizeof one);
        if (n != sizeof(one))
            LOG_ERROR << "EventLoop::WakeUpRead() reads " << n << " bytes instead of 8";
    }
    inline void EventLoop::RunExtraFunc()
    {
        std::vector<std::function<void()>> functors;
        m_runningExtraFunc = true;

        {
            std::lock_guard lock(m_mu);
            functors.swap(m_ExtraFuncs);
        }
        //既减少了持有锁的时间，也防止了死锁(func里可能也调用了RunExtraFunc()

        for (auto&& func : functors)
            func();

        m_runningExtraFunc = false;
    }
    inline void EventLoop::PrintActiveChannels() const
    {
        for (auto&& channel : m_activeChannels)
            LOG_TRACE << "{" << channel->ReventsString() << "} ";
    }
    inline void EventLoop::AssertInLoopThread()
    {
        if (!InLoopThread())
            LOG_FATAL << "EventLoop::abortNotInLoopThread - EventLoop " << this
                      << " was created in threadID_ = " << m_threadID
                      << ", current thread id = " << this_thrd::tid();
    }
    inline TimerID EventLoop::runAt(Timestamp time, std::function<void()> callback)
    {
        return timerQueue_->add(std::move(callback), time, 0.0);
    }
    inline TimerID EventLoop::runAfter(double delay, std::function<void()> callback)
    {
        Timestamp time(Timestamp::AddTime(Timestamp::now(), delay));
        return runAt(time, std::move(callback));
    }
    inline TimerID EventLoop::runEvery(double interval, std::function<void()> callback)
    {
        Timestamp time(Timestamp::AddTime(Timestamp::now(), interval));
        return timerQueue_->add(std::move(callback), time, interval);
    }
    inline void EventLoop::cancel(TimerID timerID) { return timerQueue_->cancel(timerID); }



    inline void Buffer::swap(Buffer& other)
    {
        m_vec.swap(other.m_vec);
        std::swap(m_readIndex, other.m_readIndex);
        std::swap(m_writeIndex, other.m_writeIndex);
    }
    inline const char* Buffer::FindCRLF() const
    {
        const char* crlf = std::search(BeginRead(), BeginWrite(), k_CRLF, k_CRLF + 2);
        return crlf == BeginWrite() ? NULL : crlf;
    }
    inline const char* Buffer::FindCRLF(const char* start) const
    {
        const char* crlf = std::search(start, BeginWrite(), k_CRLF, k_CRLF + 2);
        return crlf == BeginWrite() ? NULL : crlf;
    }
    inline void Buffer::drop(uint64_t len)
    {
        if (len < ReadableBytes())
            m_readIndex += len;
        else
            DropAll();
    }
    inline void Buffer::DropAll()
    {
        m_readIndex = k_PrependSize;
        m_writeIndex = k_PrependSize;
    }
    inline std::string Buffer::RetrieveAsString(uint64_t len)
    {
        std::string res(BeginRead(), len);
        drop(len);
        return res;
    }
    inline void Buffer::append(const char* data, uint64_t len)
    {
        EnsureWritableBytes(len);
        std::copy(data, data + len, BeginWrite());
        WriteIndexRightShift(len);
    }
    inline void Buffer::EnsureWritableBytes(uint64_t len)
    {
        if (WritableBytes() < len)
            MakeSpace(len);
    }
    inline void Buffer::AppendInt64(int64_t x)
    {
        int64_t val = htonll(x);
        append(&val, sizeof(val));
    }
    inline void Buffer::AppendInt32(int x)
    {
        int val = htonl(x);
        append(&val, sizeof(val));
    }
    inline void Buffer::AppendInt16(int16_t x)
    {
        int16_t val = htons(x);
        append(&val, sizeof(val));
    }
    inline int64_t Buffer::ReadInt64()
    {
        int64_t res = PeekInt64();
        DropInt64();
        return res;
    }
    inline int Buffer::ReadInt32()
    {
        int res = PeekInt32();
        DropInt32();
        return res;
    }
    inline int16_t Buffer::ReadInt16()
    {
        int16_t res = PeekInt16();
        DropInt16();
        return res;
    }
    inline int8_t Buffer::ReadInt8()
    {
        int8_t res = PeekInt8();
        DropInt8();
        return res;
    }
    inline int64_t Buffer::PeekInt64() const
    {
        int64_t val = 0;
        memcpy(&val, BeginRead(), sizeof(val));
        return ntohll(val);
    }
    inline int Buffer::PeekInt32() const
    {
        int val = 0;
        memcpy(&val, BeginRead(), sizeof(val));
        return ntohl(val);
    }
    inline int16_t Buffer::PeekInt16() const
    {
        int16_t val = 0;
        memcpy(&val, BeginRead(), sizeof(val));
        return ntohs(val);
    }
    inline void Buffer::PrependInt64(int64_t x)
    {
        int64_t val = htonll(x);
        prepend(&val, sizeof(val));
    }
    inline void Buffer::PrependInt32(int x)
    {
        int val = htonl(x);
        prepend(&val, sizeof(val));
    }
    inline void Buffer::PrependInt16(int16_t x)
    {
        int16_t val = htons(x);
        prepend(&val, sizeof(val));
    }
    inline void Buffer::prepend(const void* data, uint64_t len)
    {
        m_readIndex -= len;
        std::copy((const char*)data, (const char*)data + len, begin() + m_readIndex);
    }
    inline void Buffer::shrink(uint64_t reserve)
    {
        Buffer other;
        other.EnsureWritableBytes(reserve);
        other.append(ToStringView());
        swap(other);
    }
    inline void Buffer::MakeSpace(uint64_t len)
    {
        if (WritableBytes() + PrependableBytes() < len + k_PrependSize)
            m_vec.resize(m_writeIndex + len);  //不够就开辟一片新的地方
        else
        {  //够就把数据移到最前面,后面就是space
            uint64_t readable = ReadableBytes();
            char* p = begin();
            std::copy(p + m_readIndex, p + m_writeIndex, p + k_PrependSize);
            m_readIndex = k_PrependSize;
            m_writeIndex = m_readIndex + readable;
        }
    }
    inline ssize_t Buffer::Read(int fd, int* savedErrno)
    {
        char tmpBuf[65536];
        //两个缓冲区，一个是Buffer剩余的空间，一个是tmpbuf
        iovec vec[2];
        const uint64_t writable = WritableBytes();
        vec[0].iov_base = begin() + m_writeIndex;
        vec[0].iov_len = writable;
        vec[1].iov_base = tmpBuf;
        vec[1].iov_len = sizeof(tmpBuf);

        //如果Buffer剩余空间够，就只用Buffer剩余空间，否则还加一个tmpbuf
        const int iovecNum = (writable < sizeof(tmpBuf)) ? 2 : 1;
        const ssize_t n = detail::Readv(fd, vec, iovecNum);
        //错误
        if (n < 0)
            *savedErrno = errno;
        //Buffer空间够
        else if ((uint64_t)n <= writable)
            m_writeIndex += n;
        //Buffer空间不够
        else
        {
            m_writeIndex = m_vec.size();
            append(tmpBuf, n - writable);
        }
        return n;
    }



    TcpConnection::TcpConnection(EventLoop* loop, const std::string& name, int sockfd, const SockAddr& localAddr, const SockAddr& peerAddr)
        : m_loop(loop),
          m_highWaterMark(64 * 1024 * 1024),
          m_name(name),
          m_status(k_Connecting),
          m_reading(true),
          m_socket(std::make_unique<detail::Socket>(sockfd)),
          m_channel(std::make_unique<detail::Channel>(loop, sockfd)),
          m_localAddr(localAddr),
          m_peerAddr(peerAddr)
    {
        m_channel->SetReadCallback(std::bind(&TcpConnection::handleRead, this, std::placeholders::_1));
        m_channel->SetWriteCallback(std::bind(&TcpConnection::handleWrite, this));
        m_channel->SetCloseCallback(std::bind(&TcpConnection::handleClose, this));
        m_channel->SetErrorCallback(std::bind(&TcpConnection::handleError, this));
        LOG_DEBUG << "TcpConnection::ctor[" << m_name << "] at " << this << " fd=" << sockfd;
    }
    TcpConnection::~TcpConnection()
    {
        LOG_DEBUG << "TcpConnection::~TcpConnection [" << m_name << "] at " << this
                  << " fd=" << m_channel->fd()
                  << " state=" << StatusToString();
    }
    std::string TcpConnection::GetTcpInfoString() const
    {
        char buf[1024];
        buf[0] = '\0';
        m_socket->GetTcpInfoString(buf);
        return buf;
    }
    void TcpConnection::send(std::string&& msg)
    {
        if (m_status == k_Connected)
        {
            if (m_loop->InLoopThread())
                SendInLoop(msg.data(), msg.size());  //如果是当前线程就直接发送
            else
                //否则放到loop待执行回调队列执行,会发生拷贝
                m_loop->AddExtraFunc(std::bind(&TcpConnection::SendStringView, this, msg));
        }
    }
    void TcpConnection::send(const std::string_view& msg)
    {
        if (m_status == k_Connected)
        {
            if (m_loop->InLoopThread())
                SendInLoop(msg.data(), msg.size());  //如果是当前线程就直接发送
            else
                //否则放到loop待执行回调队列执行,会发生拷贝
                m_loop->AddExtraFunc(std::bind(&TcpConnection::SendStringView, this, std::string(msg)));
        }
    }
    void TcpConnection::send(Buffer* buf)
    {
        if (m_status == k_Connected)
        {
            if (m_loop->InLoopThread())
            {
                SendInLoop(buf->BeginRead(), buf->ReadableBytes());  //如果是当前线程就直接发送
                buf->DropAll();
            }
            else
                //否则放到loop待执行回调队列执行,会发生拷贝
                m_loop->AddExtraFunc(std::bind(&TcpConnection::SendStringView, this, buf->RetrieveAllAsString()));
        }
    }
    void TcpConnection::shutdown()
    {
        if (m_status == k_Connected)
        {
            m_status = k_Disconnecting;
            m_loop->run(std::bind(&TcpConnection::ShutdownInLoop, shared_from_this()));
        }
    }
    void TcpConnection::ForceClose()
    {
        if (m_status == k_Connected || m_status == k_Disconnecting)
        {
            m_status = k_Disconnecting;
            m_loop->AddExtraFunc(std::bind(&TcpConnection::ForceCloseInLoop, shared_from_this()));
        }
    }
    void TcpConnection::ForceCloseWithDelay(double seconds)
    {
        if (m_status == k_Connected || m_status == k_Disconnecting)
        {
            m_status = k_Disconnecting;
            m_loop->runAfter(seconds, detail::MakeWeakCallback(shared_from_this(), &TcpConnection::ForceClose));
        }
    }
    void TcpConnection::ConnectEstablished()
    {
        m_loop->AssertInLoopThread();
        m_status = k_Connected;
        m_channel->tie(shared_from_this());  //使Channel生命周期与TcpConnection对象相同
        m_channel->OnReading();              //将channel添加到Poller中
        m_connCallback(shared_from_this());  //调用用户注册的回调函数
    }
    void TcpConnection::ConnectDestroyed()
    {
        m_loop->AssertInLoopThread();
        if (m_status == k_Connected)
        {
            m_status = k_Disconnected;
            m_channel->OffAll();
            m_connCallback(shared_from_this());
        }
        m_channel->remove();
    }
    void TcpConnection::handleRead(Timestamp receiveTime)
    {
        m_loop->AssertInLoopThread();
        int savedErrno = 0;
        //尝试一次读完tcp缓冲区的所有数据,返回实际读入的字节数(一次可能读不完)
        ssize_t n = m_inputBuf.Read(m_channel->fd(), &savedErrno);
        if (n > 0)  //读成功就调用用户设置的回调函数
            m_msgCallback(shared_from_this(), &m_inputBuf, receiveTime);
        else if (n == 0)  //说明对方调用了close()
            handleClose();
        else  //出错
        {
            errno = savedErrno;
            LOG_SYSERR << "TcpConnection::handleRead";
            handleError();
        }
    }
    void TcpConnection::handleWrite()
    {
        m_loop->AssertInLoopThread();
        if (m_channel->IsWriting())
        {
            //尝试一次写完outputBuf的所有数据,返回实际写入的字节数(tcp缓冲区很有可能仍然不能容纳所有数据)
            ssize_t n = detail::Write(m_channel->fd(), m_outputBuf.BeginRead(), m_outputBuf.ReadableBytes());
            if (n > 0)
            {
                m_outputBuf.drop(n);  //调整index
                //如果写完了
                if (m_outputBuf.ReadableBytes() == 0)
                {
                    //不再监听写事件
                    m_channel->OffWriting();
                    //如果设置了写完的回调函数就进行回调
                    if (m_writeDoneCallback)
                        m_loop->AddExtraFunc(std::bind(m_writeDoneCallback, shared_from_this()));
                    if (m_status == k_Disconnecting)
                        ShutdownInLoop();
                }
            }
            else
                LOG_SYSERR << "TcpConnection::handleWrite";
        }
        else
            LOG_TRACE << "Connection fd = " << m_channel->fd() << " is down, no more writing";
    }
    void TcpConnection::handleClose()
    {
        m_loop->AssertInLoopThread();
        LOG_TRACE << "fd = " << m_channel->fd() << " state = " << StatusToString();
        m_status = k_Disconnected;
        m_channel->OffAll();

        std::shared_ptr<TcpConnection> guard = shared_from_this();
        // 此时当前的TcpConnection的引用计数为3
        //1.guard  2.在TcpServer的map中 3.在Channel的tie中(保证Channel回调时TcpConnection还活着)

        m_connCallback(guard);
        m_closeCallback(guard);
    }
    void TcpConnection::handleError()
    {
        int err = detail::GetSocketError(m_channel->fd());
        LOG_ERROR << "TcpConnection::handleError [" << m_name << "] - SO_ERROR = " << err << " " << detail::strerror_tl(err);
    }
    void TcpConnection::SendInLoop(const void* data, size_t len)
    {
        m_loop->AssertInLoopThread();
        ssize_t nwrote = 0;
        size_t remain = len;
        bool faultError = false;
        if (m_status == k_Disconnected)
        {
            LOG_WARN << "disconnected, give up writing";
            return;
        }

        //如果channel没在写数据且outputBuf为空,就直接往fd写
        //因为如果outputBuf不为空就直接往fd写,就会导致顺序出错,应先把outputBuf里的数据发完
        if (!m_channel->IsWriting() && m_outputBuf.ReadableBytes() == 0)
        {
            nwrote = detail::Write(m_channel->fd(), data, len);
            if (nwrote >= 0)
            {
                remain = len - nwrote;
                if (remain == 0 && m_writeDoneCallback)  //写完且有回调要执行
                    m_loop->AddExtraFunc(std::bind(m_writeDoneCallback, shared_from_this()));
            }
            else  //出错,一点也写不进
            {
                nwrote = 0;
                if (errno != EWOULDBLOCK)  //如果错误为EWOULDBLOCK,表明tcp缓冲区已满
                {
                    LOG_SYSERR << "TcpConnection::SendInLoop";
                    //EPIPE表示客户端已经关闭了连接
                    // ECONNRESET表示连接已重置
                    if (errno == EPIPE || errno == ECONNRESET)
                        faultError = true;
                }
            }
        }

        if (!faultError && remain > 0)  //没出错但没写完
        {
            uint64_t bufRemain = m_outputBuf.ReadableBytes();
            //到达阈值且设置了对应的回调函数,则进行回调
            if (bufRemain + remain >= m_highWaterMark && bufRemain < m_highWaterMark && m_highWaterMarkCallback)
                m_loop->AddExtraFunc(std::bind(m_highWaterMarkCallback, shared_from_this(), bufRemain + remain));
            //把剩下的数据写入outputBuf中
            m_outputBuf.append((const char*)data + nwrote, remain);
            //如果channel之前没监听写事件,就开启监听
            if (!m_channel->IsWriting())
                m_channel->OnWriting();
        }
    }
    void TcpConnection::ShutdownInLoop()
    {
        m_loop->AssertInLoopThread();
        if (!m_channel->IsWriting())
            m_socket->ShutdownWrite();
    }
    void TcpConnection::ForceCloseInLoop()
    {
        m_loop->AssertInLoopThread();
        if (m_status == k_Connected || m_status == k_Disconnecting)
            handleClose();
    }
    const char* TcpConnection::StatusToString() const
    {
        switch (m_status)
        {
            case k_Disconnected:
                return "k_Disconnected";
            case k_Connecting:
                return "k_Connecting";
            case k_Connected:
                return "k_Connected";
            case k_Disconnecting:
                return "k_Disconnecting";
            default:
                return "unknown status";
        }
    }
    void TcpConnection::StartReadInLoop()
    {
        m_loop->AssertInLoopThread();
        if (!m_reading || !m_channel->IsReading())
        {
            m_channel->OnReading();
            m_reading = true;
        }
    }
    void TcpConnection::StopReadInLoop()
    {
        m_loop->AssertInLoopThread();
        if (m_reading || m_channel->IsReading())
        {
            m_channel->OffReading();
            m_reading = false;
        }
    }



    TcpServer::TcpServer(EventLoop* loop, const SockAddr& listenAddr, const std::string& name, Option option)
        : m_nextConnID(1),
          m_acceptor(std::make_unique<detail::Acceptor>(loop, listenAddr, option == kReusePort)),
          m_loop(loop),
          m_threadPool(std::make_shared<detail::EventLoopThreadPool>(loop, name)),
          m_ipPort(listenAddr.ipPortString()),
          m_name(name),
          m_connCallback(detail::DefaultConnCallback),
          m_msgCallback(detail::DefaultMsgCallback)
    {
        using namespace std::placeholders;
        m_acceptor->SetConnectionCallback(std::bind(&TcpServer::newConnection, this, _1, _2));
    }
    void TcpServer::start()
    {
        if (!m_started)
        {
            m_started = true;
            m_threadPool->start(m_threadInitCallback);
            m_loop->run(std::bind(&detail::Acceptor::listen, m_acceptor.get()));
        }
    }
    TcpServer::~TcpServer()
    {
        m_loop->AssertInLoopThread();
        LOG_TRACE << "TcpServer::~TcpServer [" << m_name << "] destructing";

        for (auto&& item : m_connections)
        {
            std::shared_ptr<TcpConnection> conn(item.second);
            item.second.reset();
            conn->GetLoop()->run(std::bind(&TcpConnection::ConnectDestroyed, conn));
        }
    }
    void TcpServer::newConnection(int sockfd, const SockAddr& peerAddr)
    {
        m_loop->AssertInLoopThread();
        EventLoop* ioLoop = m_threadPool->GetNextLoop();  //取出一个EventLoop
        char buf[64] = {0};
        fmt::format_to(buf, "-{}#{}", m_ipPort.c_str(), m_nextConnID++);
        std::string connName = m_name + buf;

        // LOG_INFO << "TcpServer::newConnection [" << m_name << "] - new connection [" << connName << "] from "
        //          << peerAddr.ipPortString();

        //创建新的TcpConnection
        SockAddr localAddr(detail::GetLocalAddr(sockfd));
        auto& conn = m_connections[connName] = std::make_shared<TcpConnection>(ioLoop, connName, sockfd, localAddr, peerAddr);

        //TcpServer将所有回调函数都传给新的TcpConnection
        conn->setConnectionCallback(m_connCallback);
        conn->setMessageCallback(m_msgCallback);
        conn->setWriteCompleteCallback(m_writeDoneCallback);
        //关闭回调函数,作用是将这个关闭的TcpConnection从map中删除
        conn->setCloseCallback(std::bind(&TcpServer::removeConnection, this, std::placeholders::_1));
        ioLoop->run(std::bind(&TcpConnection::ConnectEstablished, std::ref(conn)));
    }
    void TcpServer::removeConnection(const std::shared_ptr<TcpConnection>& conn)
    {
        // FIXME 不安全
        //因为调用TcpServer::removeConnection的线程是TcpConnection所在的EventLoop
        //也就是说TcpServer的this指针暴露在TcpConnection所在的EventLoop了
        //如果这个EventLoop对这个this指针做修改,就可能会导致TcpServer出错
        //所以理论上是不安全的,但其实并没有修改,而是立刻进入到TcpServer的EventLoop,所以其实是安全的
        //硬要说不安全,只有下面这一句话理论上不安全(其实也安全),其他全都是安全的
        m_loop->run(std::bind(&TcpServer::removeConnectionInLoop, this, conn));
    }
    void TcpServer::removeConnectionInLoop(const std::shared_ptr<TcpConnection>& conn)
    {
        m_loop->AssertInLoopThread();

        LOG_INFO << "TcpServer::removeConnectionInLoop [" << m_name << "] - connection " << conn->name();
        m_connections.erase(conn->name());

        //不直接用m_loop->run是因为TcpConnection::ConnectDestroyed应该交给其对应的EventLoop执行
        conn->GetLoop()->AddExtraFunc(std::bind(&TcpConnection::ConnectDestroyed, conn));
        //此时conn引用计数为2
        //1.conn本身   2.上面bind了一个
        //所以离开这个函数后就只剩1,然后执行完TcpConnection::ConnectDestroyed,对应的TcpConnection才真正析构
    }



}  // namespace kurisu