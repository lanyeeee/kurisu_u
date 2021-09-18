#include <string>
#include <string.h>
#include <string_view>
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
#include <set>
#include <any>

#include "kurisu.h"
#include "fmt/chrono.h"
#include "fmt/compile.h"

uint64_t htonll(uint64_t val) { return htobe64(val); }
uint64_t ntohll(uint64_t val) { return be64toh(val); }

namespace kurisu {

    const std::chrono::system_clock::time_point Timestamp::s_invalid;

    namespace this_thrd {
        namespace detail {
            pid_t GetTid() { return (pid_t)syscall(SYS_gettid); }
            std::string Demangle(const char* symbol)
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

        __thread int t_cachedTid;  //tid的缓存，提高效率(不用每次都调用系统函数)
        __thread char t_tidString[32] = {0};
        __thread int t_tidStringLength;
        __thread const char* t_threadName;

        void CacheTid()
        {
            if (t_cachedTid == 0)
            {
                t_cachedTid = detail::GetTid();
                char* p = fmt::format_to(t_tidString, FMT_COMPILE("{:5d}"), t_cachedTid);
                t_tidStringLength = (int)(p - t_tidString);
            }
        }
        int Tid()
        {
            if (t_cachedTid == 0)
                CacheTid();
            return t_cachedTid;
        }
        const char* TidString() { return t_tidString; }
        int TidStringLength() { return t_tidStringLength; }
        const char* Name() { return t_threadName; }

        bool IsMainThread() { return Tid() == getpid(); }
        void SleepFor(int us) { std::this_thread::sleep_for(std::chrono::microseconds(us)); }
        std::string StackTrace()
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
            bool mainThreadInit = [] {
                t_threadName = "main";
                CacheTid();
                pthread_atfork(NULL, NULL, [] {
                    t_threadName = "main";
                    t_cachedTid = 0;
                    CacheTid();
                });
                return 0;
            }();
        }
    }  // namespace this_thrd


    namespace detail {

        void CountDownLatch::Wait()
        {
            std::unique_lock locker(m_mu);
            while (m_count > 0)
                m_cond.wait(locker, [this] { return m_count == 0; });
        }
        void CountDownLatch::CountDown()
        {
            std::lock_guard locker(m_mu);
            m_count--;
            if (m_count == 0)
                m_cond.notify_all();
        }
        int CountDownLatch::GetCount() const
        {
            std::lock_guard locker(m_mu);
            return m_count;
        }



        void ThreadData::Run()
        {
            m_tid = this_thrd::Tid();
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
        void ThrdEntrance(std::shared_ptr<ThreadData> thrdData) { thrdData->Run(); }


        //效率很高的pointer->str算法
        uint64_t ConvertHex(char buf[], uintptr_t value)
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

        ReadSmallFile::ReadSmallFile(StringArg filepath) : m_fd(open(filepath.c_str(), O_RDONLY | O_CLOEXEC)), m_err(0)
        {
            m_buf[0] = '\0';
            if (m_fd < 0)
                m_err = errno;
        }
        ReadSmallFile::~ReadSmallFile()
        {
            if (m_fd >= 0)
                close(m_fd);
        }
        int ReadSmallFile::ReadToString(int maxSize, std::string& content, int64_t* fileSize, int64_t* modifyTime, int64_t* createTime)
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
        int ReadSmallFile::ReadToBuffer(int* size)
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
        int ReadFile(StringArg filepath, int maxSize, std::string& content, int64_t* fileSize, int64_t* modifyTime, int64_t* createTime)
        {
            ReadSmallFile file(filepath);
            return file.ReadToString(maxSize, content, fileSize, modifyTime, createTime);
        }

        __thread int t_numOpenedFiles = 0;
        int FdDirFilter(const struct dirent* d)
        {
            if (isdigit(d->d_name[0]))
                ++t_numOpenedFiles;
            return 0;
        }

        __thread std::vector<pid_t>* t_pids = nullptr;
        int TaskDirFilter(const struct dirent* d)
        {
            if (isdigit(d->d_name[0]))
                detail::t_pids->emplace_back(atoi(d->d_name));
            return 0;
        }

        int ScanDir(const char* dirpath, int (*filter)(const struct dirent*))
        {
            struct dirent** namelist = nullptr;
            return scandir(dirpath, &namelist, filter, alphasort);
        }

        Timestamp g_startTime = Timestamp::Now();
        // assume those won't change during the life time of a process.
        int g_clockTicks = (int)sysconf(_SC_CLK_TCK);
        int g_pageSize = (int)sysconf(_SC_PAGE_SIZE);

        __thread char t_errnobuf[512];  //缓存errno的str
        __thread char t_time[64];       //缓存时间的str
        __thread int64_t t_lastSecond;  //上次缓存t_time的时间
        //生成errno的str
        const char* strerror_tl(int savedErrno) { return strerror_r(savedErrno, t_errnobuf, sizeof(t_errnobuf)); }

        void LogFileAppender::Append(const char* logline, const uint64_t len)
        {
            uint64_t written = 0;
            while (written != len)
            {
                uint64_t remain = len - written;
                uint64_t n = Write(logline + written, remain);
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


        std::atomic_int32_t Thread::s_createdNum = 0;

        Thread::~Thread()
        {
            if (m_started && m_thrd.joinable())
                m_thrd.detach();
        }
        void Thread::SetDefaultName()
        {
            ++s_createdNum;
            if (m_name.empty())
                m_name = fmt::format("Thread{}", s_createdNum);
        }
        void Thread::Start()
        {
            using namespace detail;
            m_started = true;
            auto thrdData = std::make_shared<ThreadData>(std::move(m_func), m_name, m_tid, m_latch);
            m_thrd = std::thread(ThrdEntrance, thrdData);
            m_pthreadID = m_thrd.native_handle();
            m_latch.Wait();
        }




        ThreadPool::~ThreadPool()
        {
            if (m_running)
                Stop();
        }
        void ThreadPool::SetThrdNum(int thrdNum)
        {
            m_running = 1;
            m_thrds.reserve(thrdNum);
            for (int i = 0; i < thrdNum; i++)
            {
                std::string id = fmt::format("{}", i + 1);
                auto res = m_name + id;
                m_thrds.emplace_back(std::make_unique<Thread>(std::bind(&kurisu::detail::ThreadPool::Handle, this), m_name + id));  //创建线程
                m_thrds[i]->Start();
            }

            if (thrdNum == 0 && m_thrdInitCallBack)  //如果创建的线程为0，也执行初始化后的回调函数
                m_thrdInitCallBack();
        }
        void ThreadPool::Handle()
        {
            try
            {
                if (m_thrdInitCallBack)
                    m_thrdInitCallBack();  //如果有初始化的回调函数就执行
                while (m_running)
                    if (std::function<void()> func(Take()); func)  //从函数队列中拿出函数，是可执行的函数就执行，直到m_running被变成false
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
        std::function<void()> ThreadPool::Take()
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
        void ThreadPool::Run(std::function<void()> task)
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
                if (Full() && m_running)
                    m_notFullCond.wait(locker, [this] { return !Full() || !m_running; });  //线程池中的线程都忙，就等到有空闲的线程为止

                if (!m_running)  //如果已经析构，线程退出
                    return;

                m_task.emplace_back(std::move(task));  //将task加入队列
                //printf("m_task.size()=%lu\n", m_task.size());
                m_notEmptyCond.notify_one();  //通知其他线程等待队列已有任务
            }
        }
        void ThreadPool::Stop()
        {
            {
                std::lock_guard locker(m_mu);
                m_running = 0;
                m_notFullCond.notify_all();
                m_notEmptyCond.notify_all();
            }
            for (auto&& thrd : m_thrds)
                thrd->Join();
        }
        void ThreadPool::Join()
        {
            detail::CountDownLatch latch(1);

            //往线程池里加入一个倒计时任务
            Run(std::bind(&kurisu::detail::CountDownLatch::CountDown, &latch));

            //等待倒计时任务被执行
            //被执行了就说明在这个任务之前的任务都被执行了
            latch.Wait();
            Stop();
        }
        uint64_t ThreadPool::Size() const
        {
            std::lock_guard locker(m_mu);
            return m_task.size();
        }
        bool ThreadPool::Full() const { return m_maxSize > 0 && m_task.size() >= m_maxSize; }




        LogStream& LogStream::operator<<(bool val)
        {
            m_buf.Append(val ? "1" : "0", 1);
            return *this;
        }
        LogStream& LogStream::operator<<(char val)
        {
            m_buf.Append(&val, 1);
            return *this;
        }
        LogStream& LogStream::operator<<(int16_t val)
        {
            *this << (int)val;
            return *this;
        }
        LogStream& LogStream::operator<<(uint16_t val)
        {
            *this << (uint32_t)val;
            return *this;
        }
        LogStream& LogStream::operator<<(int val)
        {
            FormatInt(val);
            return *this;
        }
        LogStream& LogStream::operator<<(uint32_t val)
        {
            FormatInt(val);
            return *this;
        }
        LogStream& LogStream::operator<<(int64_t val)
        {
            FormatInt(val);
            return *this;
        }
        LogStream& LogStream::operator<<(uint64_t val)
        {
            FormatInt(val);
            return *this;
        }
        LogStream& LogStream::operator<<(float val)
        {
            *this << (double)val;
            return *this;
        }
        LogStream& LogStream::operator<<(double val)
        {
            if (m_buf.AvalibleSize() >= k_MaxSize)
            {
                auto ptr = fmt::format_to(m_buf.Index(), FMT_COMPILE("{:.12g}"), val);
                uint64_t len = ptr - m_buf.Index();
                m_buf.IndexShiftRight(len);
            }
            return *this;
        }
        LogStream& LogStream::operator<<(const void* p)
        {
            uintptr_t val = (uintptr_t)p;
            if (m_buf.AvalibleSize() >= k_MaxSize)
            {
                char* buf = m_buf.Index();
                buf[0] = '0';
                buf[1] = 'x';
                uint64_t len = detail::ConvertHex(buf + 2, val);
                m_buf.IndexShiftRight(len + 2);
            }
            return *this;
        }
        LogStream& LogStream::operator<<(const char* p)
        {
            if (p)
                m_buf.Append(p, strlen(p));
            else
                m_buf.Append("(null)", 6);
            return *this;
        }
        LogStream& LogStream::operator<<(const unsigned char* p)
        {
            *this << (const char*)p;
            return *this;
        }
        LogStream& LogStream::operator<<(const std::string& str)
        {
            m_buf.Append(str.data(), str.size());
            return *this;
        }
        LogStream& LogStream::operator<<(const std::string_view& str)
        {
            m_buf.Append(str.data(), str.size());
            return *this;
        }
        LogStream& LogStream::operator<<(const FixedBuf& buf)
        {
            *this << buf.StringView();
            return *this;
        }
        LogStream& LogStream::operator<<(const detail::KnownLengthString& str)
        {
            m_buf.Append(str.m_buf, str.m_size);
            return *this;
        }

    }  // namespace detail

    bool Logger::s_isLocalTimeZone = false;

    namespace detail {
        void DefaultOutput(const char* msg, const uint64_t len) { fwrite(msg, 1, len, stdout); }
        void DefaultFlush() { fflush(stdout); }
        Logger::LogLevel InitLogLevel()
        {
            if (getenv("KURISU_LOG_TRACE"))
                return Logger::LogLevel::TRACE;
            else if (getenv("KURISU_LOG_DEBUG"))
                return Logger::LogLevel::DEBUG;
            else
                return Logger::LogLevel::INFO;
        }

        void (*g_output)(const char* msg, const uint64_t len) = DefaultOutput;
        void (*g_flush)() = DefaultFlush;
        Logger::LogLevel g_logLevel = InitLogLevel();
        const char* LogLevelName[6] = {
            "[TRACE] ",
            "[DEBUG] ",
            "[INFO]  ",
            "[WARN]  ",
            "[ERROR] ",
            "[FATAL] ",
        };

    }  // namespace detail

    namespace process {
        pid_t Pid() { return getpid(); }
        std::string PidString() { return fmt::format("{}", Pid()); }
        uid_t Uid() { return getuid(); }
        std::string UserName()
        {
            struct passwd pwd;
            struct passwd* result = nullptr;
            char buf[8192];
            const char* name = "unknownuser";

            getpwuid_r(Uid(), &pwd, buf, sizeof buf, &result);
            if (result)
                name = pwd.pw_name;
            return name;
        }
        Timestamp StartTime() { return detail::g_startTime; }
        int ClockTicksPerSecond() { return detail::g_clockTicks; }
        int PageSize() { return detail::g_pageSize; }


        // read /proc/self/status
        std::string ProcStatus()
        {
            std::string result;
            detail::ReadFile("/proc/self/status", 65536, result);
            return result;
        }
        // read /proc/self/stat
        std::string ProcStat()
        {
            std::string result;
            detail::ReadFile("/proc/self/stat", 65536, result);
            return result;
        }
        // read /proc/self/task/tid/stat
        std::string ThreadStat()
        {
            char buf[64] = {0};
            fmt::format_to(buf, "/proc/self/task/{}/stat", this_thrd::Tid());
            std::string result;
            detail::ReadFile(buf, 65536, result);
            return result;
        }
        // readlink /proc/self/exe
        std::string ExePath()
        {
            std::string result;
            char buf[1024];
            ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf));
            if (n > 0)
                result.assign(buf, n);
            return result;
        }

        std::string HostName()
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
        std::string_view ProcName(const std::string& stat)
        {
            std::string_view name;
            uint64_t lp = stat.find('(');
            uint64_t rp = stat.rfind(')');
            if (lp != std::string_view::npos && rp != std::string_view::npos && lp < rp)
                name = std::string_view(stat.data() + lp + 1, (int)(rp - lp - 1));
            return name;
        }
        std::string ProcName() { return ProcName(ProcStat()).data(); }

        int OpenedFiles()
        {
            using namespace detail;
            t_numOpenedFiles = 0;
            ScanDir("/proc/self/fd", FdDirFilter);
            return t_numOpenedFiles;
        }
        int MaxOpenFiles()
        {
            struct rlimit rl;
            if (getrlimit(RLIMIT_NOFILE, &rl))
                return OpenedFiles();
            else
                return (int)rl.rlim_cur;
        }

        int ThreadNum()
        {
            int result = 0;
            std::string status = ProcStatus();
            size_t pos = status.find("Threads:");
            if (pos != std::string::npos)
                result = atoi(status.c_str() + pos + 8);
            return result;
        }

        std::vector<pid_t> Threads()
        {
            std::vector<pid_t> result;
            detail::t_pids = &result;
            detail::ScanDir("/proc/self/task", detail::TaskDirFilter);
            detail::t_pids = NULL;
            std::sort(result.begin(), result.end());
            return result;
        }

    }  // namespace process


    namespace detail {
        socklen_t SizeofSockAddr(SockAddr* addr)
        {
            if (addr->Famliy() == AF_INET)
                return sizeof(struct sockaddr_in);
            else
                return sizeof(struct sockaddr_in6);
        }

        int MakeNonblockingSocket(sa_family_t family)
        {
            int sockfd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
            if (sockfd < 0)
                LOG_SYSFATAL << "Socket::MakeNonblockingSocket";
            return sockfd;
        }
        int Connect(int sockfd, SockAddr* addr) { return connect(sockfd, &addr->As_sockaddr(), SizeofSockAddr(addr)); }
        void Bind(int sockfd, SockAddr* addr)
        {
            if (int res = bind(sockfd, &addr->As_sockaddr(), SizeofSockAddr(addr)); res < 0)
                LOG_SYSFATAL << "Socket::BindAndListen  bind";
        }
        void Listen(int sockfd)
        {
            if (int res = listen(sockfd, SOMAXCONN); res < 0)
                LOG_SYSFATAL << "Socket::BindAndListen  listen";
        }
        int Accept(int sockfd, SockAddr* addr)
        {
            socklen_t addrlen = sizeof(*addr);

            //将fd直接设为非阻塞
            //FIXME  IPv6可以吗
            int connfd = accept4(sockfd, &addr->As_sockaddr(), &addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
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


        void Close(int sockfd)
        {
            if (close(sockfd) < 0)
                LOG_SYSERR << "Sockets::Close";
        }

        void ShutdownWrite(int sockfd)
        {
            if (shutdown(sockfd, SHUT_WR) < 0)
                LOG_SYSERR << "Sockets::ShutdownWrite";
        }

        void IpProtToAddr(uint16_t port, const char* host, SockAddr* addr)
        {
            // addr->sin_port = htons(port);
            sockaddr_in& sin = addr->As_sockaddr_in();
            sockaddr_in6& sin6 = addr->As_sockaddr_in6();

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
                memcpy(&addr->As_sockaddr(), ais->ai_addr, ais->ai_addrlen);
                freeaddrinfo(ais);
            }
            if (addr->Famliy() == AF_INET)
                sin.sin_port = htons(port);
            else
                sin6.sin6_port = htons(port);
        }

        void AddrToIp(char* buf, uint64_t size, SockAddr* addr)
        {
            if (addr->Famliy() == AF_INET)
                inet_ntop(AF_INET, &addr->As_sockaddr_in().sin_addr, buf, (socklen_t)size);
            else if (addr->Famliy() == AF_INET6)
                inet_ntop(AF_INET6, &addr->As_sockaddr_in6().sin6_addr, buf, (socklen_t)size);
        }

        void AddrToIpPort(char* buf, uint64_t size, SockAddr* addr)
        {
            if (addr->Famliy() == AF_INET)
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

        int GetSocketError(int sockfd)
        {
            int optval;
            socklen_t optlen = sizeof(optval);

            if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) < 0)
                return errno;
            else
                return optval;
        }

        SockAddr GetLocalAddr(int sockfd)
        {
            SockAddr localaddr;
            bzero(&localaddr, sizeof(SockAddr));
            socklen_t addrlen = sizeof(SockAddr);
            if (getsockname(sockfd, &localaddr.As_sockaddr(), &addrlen) < 0)
                LOG_SYSERR << "Sockets::GetLocalAddr";
            return localaddr;
        }
        SockAddr GetPeerAddr(int sockfd)
        {
            SockAddr peeraddr;
            bzero(&peeraddr, sizeof(SockAddr));
            socklen_t addrlen = sizeof(SockAddr);
            if (getpeername(sockfd, &peeraddr.As_sockaddr(), &addrlen) < 0)
                LOG_SYSERR << "Sockets::GetPeerAddr";
            return peeraddr;
        }

        int MakeNonblockingTimerfd()
        {
            int timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
            if (timerfd < 0)
                LOG_SYSFATAL << "Failed in MakeNonblockingTimerfd";
            return timerfd;
        }

        timespec HowMuchTimeFromNow(Timestamp when)
        {
            Timestamp now;
            int64_t ns = when.Nsec() - now.Nsec();
            if (ns <= 0)
                ns = 1;

            timespec ts;
            ts.tv_sec = (time_t)(ns / 1'000'000'000);
            ts.tv_nsec = ns % 1'000'000'000;
            return ts;
        }

        void ResetTimerfd(int timerfd, Timestamp runtime)
        {
            itimerspec newValue;
            itimerspec oldValue;
            bzero(&newValue, sizeof(newValue));
            bzero(&oldValue, sizeof(oldValue));
            newValue.it_value = HowMuchTimeFromNow(runtime);

            timerfd_settime(timerfd, 0, &newValue, &oldValue);
        }


        bool Socket::GetTcpInfo(tcp_info* tcpi) const
        {
            socklen_t len = sizeof(*tcpi);
            bzero(tcpi, len);
            return getsockopt(m_fd, SOL_TCP, TCP_INFO, tcpi, &len) == 0;
        }
        bool Socket::GetTcpInfoString(char* buf) const
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
        void Socket::SetTcpNoDelay(bool on)
        {
            int optval = on ? 1 : 0;
            setsockopt(m_fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
        }
        void Socket::SetReuseAddr(bool on)
        {
            int optval = on ? 1 : 0;
            setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
        }
        void Socket::SetReusePort(bool on)
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


    }  // namespace detail



    namespace detail {
        //当前线程EventLoop对象指针
        __thread EventLoop* t_loopOfThisThread = nullptr;

        const int k_PollTimeoutMs = 10000;

        int CreateEventfd()
        {
            if (int evtfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC); evtfd < 0)
            {
                LOG_SYSERR << "Failed in eventfd";
                abort();
            }
            else
                return evtfd;
        }

        void ReadTimerfd(int timerfd, Timestamp now)
        {
            uint64_t tmp;
            ssize_t n = read(timerfd, &tmp, sizeof(tmp));
            LOG_TRACE << "TimerQueue::ReadTimerfd() " << tmp << " at " << now.GmFormatString() << "(GM)";
            if (n != sizeof(tmp))
                LOG_ERROR << "TimerQueue::ReadTimerfd() reads " << n << " bytes instead of 8";
        }

        bool ignoreSigPipe = [] { return signal(SIGPIPE, SIG_IGN); }();
        bool setRandomSeed = [] { srand((uint32_t)time(0)); return 0; }();







        EventLoopThread::~EventLoopThread()
        {
            m_exiting = true;
            if (m_loop != nullptr)
            {
                m_loop->Quit();
                m_thrd.Join();
            }
        }
        EventLoop* EventLoopThread::Start()
        {
            m_thrd.Start();
            std::unique_lock locker(m_mu);
            //如果初始化未完成
            if (m_loop == nullptr)
                m_cond.wait(locker, [this] { return m_loop != nullptr; });  //等待初始化完成
            return m_loop;
        }
        void EventLoopThread::Handle()
        {
            EventLoop loop;
            loop.SetShutdownTimingWheel(m_shutdownInterval);
            loop.SetHeartbeatTimingWheel(m_heartbeatInterval);

            if (m_threadInitCallback)
                m_threadInitCallback(&loop);

            {
                std::lock_guard locker(m_mu);
                m_loop = &loop;
                m_cond.notify_one();
            }

            loop.Loop();
            std::lock_guard locker(m_mu);
            m_loop = nullptr;
        }




        EventLoopThreadPool::EventLoopThreadPool(EventLoop* loop, const std::string& name)
            : m_loop(loop), m_name(name) {}
        void EventLoopThreadPool::Start(int shutdownInterval,
                                        int heartbeatInterval,
                                        const std::function<void(EventLoop*)>& threadInitCallback)
        {
            m_loop->AssertInLoopThread();
            m_started = true;
            //创建m_thrdNum个线程，每个线程都用threadInitCallback进行初始化
            for (int i = 0; i < m_thrdNum; i++)
            {
                char name[m_name.size() + 32] = {0};
                fmt::format_to(name, "{}{}", m_name.c_str(), i);
                EventLoopThread* p = new EventLoopThread(shutdownInterval, heartbeatInterval, threadInitCallback, name);
                m_thrds.emplace_back(std::unique_ptr<EventLoopThread>(p));
                m_loops.emplace_back(p->Start());
            }
            //如果m_thrdNum == 0,就用当前线程执行threadInitCallback
            if (m_thrdNum == 0)
            {
                m_loop->SetShutdownTimingWheel(shutdownInterval);
                m_loop->SetHeartbeatTimingWheel(heartbeatInterval);
                if (threadInitCallback)
                    threadInitCallback(m_loop);
            }
        }
        EventLoop* EventLoopThreadPool::GetNextLoop()
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
        EventLoop* EventLoopThreadPool::GetLoopRandom()
        {
            m_loop->AssertInLoopThread();
            if (!m_loops.empty())
                return m_loops[rand() % m_loops.size()];
            return m_loop;
        }
        std::vector<EventLoop*> EventLoopThreadPool::GetAllLoops()
        {
            m_loop->AssertInLoopThread();
            if (m_loops.empty())
                return std::vector<EventLoop*>(1, m_loop);  //没有就造一个
            else
                return m_loops;
        }




        void Channel::RunCallback(Timestamp timestamp)
        {
            if (m_tied)
            {
                if (std::shared_ptr<void> guard = m_tie.lock(); guard)  //如果绑定的对象还活着
                    RunCallbackWithGuard(timestamp);
            }
            else
                RunCallbackWithGuard(timestamp);
        }
        void Channel::Tie(const std::shared_ptr<void>& obj)
        {
            m_tie = obj;
            m_tied = true;
        }
        void Channel::Remove()
        {
            m_inLoop = false;
            m_loop->RemoveChannel(this);
        }
        std::string Channel::EventsToString(int fd, int ev)
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
        void Channel::Update()
        {
            m_inLoop = true;
            m_loop->UpdateChannel(this);
        }
        void Channel::RunCallbackWithGuard(Timestamp timestamp)
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
        void Channel::OnReading()
        {
            m_events |= k_ReadEvent;
            Update();
        }
        void Channel::OffReading()
        {
            m_events &= ~k_ReadEvent;
            Update();
        }
        void Channel::OnWriting()
        {
            m_events |= k_WriteEvent;
            Update();
        }
        void Channel::OffWriting()
        {
            m_events &= ~k_WriteEvent;
            Update();
        }
        void Channel::OffAll()
        {
            m_events = k_NoneEvent;
            Update();
        }



        Timestamp Poller::Poll(int timeoutMs, std::vector<Channel*>* activeChannels)
        {
            LOG_TRACE << "fd total count " << m_channels.size();
            activeChannels->clear();  //删除所有active channel
            int eventsNum = epoll_wait(m_epollfd, m_events.data(), (int)m_events.size(), timeoutMs);

            int tmpErrno = errno;
            Timestamp now;
            if (eventsNum > 0)
            {
                LOG_TRACE << eventsNum << " events happened";
                for (int i = 0; i < eventsNum; i++)
                {
                    Channel* channel = (Channel*)m_events[i].data.ptr;
                    channel->SetRevents(m_events[i].events);
                    activeChannels->emplace_back(channel);
                }
                if ((uint64_t)eventsNum == m_events.size())
                    m_events.resize(m_events.size() * 2);  //说明m_events的大小要不够用了，扩容
            }
            else if (eventsNum == 0)
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
        void Poller::UpdateChannel(Channel* channel)
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
                Update(EPOLL_CTL_ADD, channel);  //将channel对应的fd注册到epoll中
            }
            else  //修改
            {
                if (channel->IsNoneEvent())  //此channel是否未注册事件
                {
                    Update(EPOLL_CTL_DEL, channel);  //直接从epoll中删除
                    channel->SetStatus(k_Deleted);   //只代表不在epoll中，不代表已经从ChannelMap中移除
                }
                else
                    Update(EPOLL_CTL_MOD, channel);  //修改(更新)事件
            }
        }
        bool Poller::HasChannel(Channel* channel) const
        {
            AssertInLoopThread();
            auto it = m_channels.find(channel->fd());
            return it != m_channels.end() && it->second == channel;
        }
        void Poller::RemoveChannel(Channel* channel)
        {
            Poller::AssertInLoopThread();
            int fd = channel->fd();
            LOG_TRACE << "fd = " << fd;
            int status = channel->GetStatus();
            m_channels.erase(fd);  //从ChannelMap中移除

            if (status == k_Added)               //如果已在epoll中注册
                Update(EPOLL_CTL_DEL, channel);  //就从epoll中移除
            channel->SetStatus(k_New);
        }
        const char* Poller::OperationString(int operatoin)
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
        void Poller::Update(int operation, Channel* channel)
        {
            epoll_event event;
            bzero(&event, sizeof(event));
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



        TimerQueue::TimerQueue(EventLoop* loop)
            : m_timerfd(detail::MakeNonblockingTimerfd()), m_loop(loop), m_timerfdChannel(loop, m_timerfd)
        {
            m_timerfdChannel.SetReadCallback(std::bind(&TimerQueue::Handle, this));
            m_timerfdChannel.OnReading();
        }
        TimerQueue::~TimerQueue()
        {
            m_timerfdChannel.OffAll();
            m_timerfdChannel.Remove();
            detail::Close(m_timerfd);
        }
        TimerID TimerQueue::Add(std::function<void()> callback, Timestamp when, double interval)
        {
            detail::Timer* timer = new detail::Timer(std::move(callback), when, interval);
            //在IO线程中执行addTimerInLoop,保证线程安全
            m_loop->Run(std::bind(&TimerQueue::AddInLoop, this, timer));

            return TimerID(timer);
        }
        void TimerQueue::AddInLoop(detail::Timer* timer)
        {
            m_loop->AssertInLoopThread();
            //插入一个Timer，有可能会使得最早到期的时间发生改变
            bool earliestChanged = Insert(timer);
            //如果发生改变，就要重置最早到期的时间
            if (earliestChanged)
                detail::ResetTimerfd(m_timerfd, timer->GetRuntime());
        }
        void TimerQueue::CancelInLoop(TimerID id)
        {
            m_loop->AssertInLoopThread();

            if (auto p = m_timers.find(id.Key()); p != m_timers.end())
            {
                if (!m_runningCallback)
                    m_timers.erase(p);
                else
                    m_cancelledSoon.emplace_back(p->second.get());
            }
        }
        void TimerQueue::Handle()
        {
            m_loop->AssertInLoopThread();
            Timestamp now;
            detail::ReadTimerfd(m_timerfd, now);  //清理超时事件，避免一直触发  //FIXME  LT模式的弊端?

            //获取now之前的所有Timer
            TimeoutTimer timeout = GetTimeout(now);
            m_runningCallback = true;
            //调用超时Timer的回调函数
            for (auto&& item : timeout)
                item->Run();
            m_runningCallback = false;

            //重置非一次性的Timer
            Reset(timeout);
        }
        TimerQueue::TimeoutTimer TimerQueue::GetTimeout(Timestamp now)
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
        void TimerQueue::Reset(TimeoutTimer& timeout)
        {
            for (auto&& item : timeout)
                if (item->IsRepeat())
                {
                    item->Restart();
                    m_timers[std::make_pair(item->GetRuntime(), item.get())] = std::move(item);
                }

            for (auto&& it : m_cancelledSoon)
                m_timers.erase(it.Key());
            m_cancelledSoon.clear();

            detail::ResetTimerfd(m_timerfd, m_timers.begin()->second->GetRuntime());
        }
        bool TimerQueue::Insert(detail::Timer* timer)
        {
            bool earliestChanged = false;
            Timestamp when = timer->GetRuntime();  //取出timer的到期时间

            //如果set为空或此timer比set中最早的timer还早
            if (m_timers.empty() || when < m_timers.begin()->first.first)
                earliestChanged = true;  //就需要修改超时时间

            m_timers[std::make_pair(when, timer)] = std::unique_ptr<detail::Timer>(timer);
            return earliestChanged;
        }



        Acceptor::Acceptor(EventLoop* loop, const SockAddr& listenAddr, bool reuseport)
            : m_loop(loop),
              m_sock(detail::MakeNonblockingSocket(listenAddr.Famliy())),
              m_channel(loop, m_sock.fd()),
              m_listening(false),
              m_voidfd(open("/dev/null", O_RDONLY | O_CLOEXEC))  //预先准备一个空闲的fd
        {
            m_sock.SetReuseAddr(true);  //设置SO_REUSEADDR,如果这个端口处于TIME_WAIT,也可bind成功

            m_sock.SetReusePort(reuseport);  //  设置SO_REUSEPORT,作用是支持多个进程或线程绑定到同一端口
                                             // 内核会采用负载均衡的的方式分配客户端的连接请求给某一个进程或线程

            m_sock.bind((SockAddr*)&listenAddr);
            m_channel.SetReadCallback(std::bind(&Acceptor::Handle, this));
        }
        Acceptor::~Acceptor()
        {
            m_channel.OffAll();
            m_channel.Remove();
            detail::Close(m_voidfd);
        }
        void Acceptor::Listen()
        {
            m_loop->AssertInLoopThread();
            m_listening = true;
            m_sock.listen();
            m_channel.OnReading();
        }
        void Acceptor::Handle()
        {
            m_loop->AssertInLoopThread();
            SockAddr peerAddr;

            if (int connfd = m_sock.accept(&peerAddr); connfd >= 0)
            {
                if (m_connectionCallback)
                    m_connectionCallback(connfd, peerAddr);
                else
                    detail::Close(connfd);
            }
            else  //FIXME  因为epoll不是ET模式，需要这样来防止因fd过多处理不了而导致epoll繁忙
            {
                LOG_SYSERR << "in Acceptor::HandleRead";
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

    const char Buffer::k_CRLF[] = "\r\n";




    namespace detail {

        int HeartbeatTimingWheel::Msg::m_len = 4;
        std::unique_ptr<char> HeartbeatTimingWheel::Msg::m_msg = std::unique_ptr<char>(new char[4]{0, 0, 0, 0});



        void DefaultConnCallback(const std::shared_ptr<kurisu::TcpConnection>& conn)
        {
            LOG_TRACE << conn->LocalAddr().ipPortString() << " -> "
                      << conn->PeerAddr().ipPortString() << " is "
                      << (conn->Connected() ? "Connected" : "Disconnected");
        }
        void DefaultMsgCallback(const std::shared_ptr<kurisu::TcpConnection>&, kurisu::Buffer* buf, kurisu::Timestamp)
        {
            buf->DiscardAll();
        }
    }  // namespace detail





    char* Timestamp::GmLogFormat(char* buf) const
    {
        uint64_t us = Usec() - Sec() * 1'000'000;
        return fmt::format_to(buf, FMT_COMPILE("[{:%F %T}.{:06}] "), fmt::gmtime(m_stamp), us);
    }
    char* Timestamp::LocalLogFormat(char* buf) const
    {
        uint64_t us = Usec() - Sec() * 1'000'000;
        return fmt::format_to(buf, FMT_COMPILE("[{:%F %T}.{:06}] "), fmt::localtime(m_stamp), us);
    }
    int64_t Timestamp::Usec() const
    {
        using namespace std::chrono;
        return duration_cast<microseconds>(m_stamp.time_since_epoch()).count();
    }
    int64_t Timestamp::Nsec() const
    {
        using namespace std::chrono;
        return duration_cast<nanoseconds>(m_stamp.time_since_epoch()).count();
    }
    int64_t Timestamp::Sec() const
    {
        using namespace std::chrono;
        return duration_cast<seconds>(m_stamp.time_since_epoch()).count();
    }
    double Timestamp::TimeDifference(Timestamp high, Timestamp low)
    {
        using namespace std::chrono;
        auto a = duration_cast<microseconds>(high.GetStamp().time_since_epoch()).count();
        auto b = duration_cast<microseconds>(low.GetStamp().time_since_epoch()).count();
        return (double)(a - b) / 1'000'000;
    }
    Timestamp Timestamp::AddTime(Timestamp stamp, double second)
    {
        using namespace std::chrono;
        uint64_t s = (uint64_t)second;
        uint64_t us = (uint64_t)((second - (double)s) * 1'000'000);
        return Timestamp(stamp.GetStamp() + seconds(s) + microseconds(us));
    }
    std::string Timestamp::GmFormatString() const { return fmt::format(FMT_COMPILE("{:%F %T}"), fmt::gmtime(m_stamp)); }
    std::string Timestamp::LocalFormatString() const { return fmt::format(FMT_COMPILE("{:%F %T}"), fmt::localtime(m_stamp)); }



    Logger::Formatter::Formatter(LogLevel level, int savedErrno, std::string_view file, int line)
        : m_time(Timestamp::Now()), m_strm(), m_level(level), m_line(line)
    {
        if (auto slash = file.rfind('/'); slash != std::string_view::npos)
        {
            file = file.substr(slash + 1);
            m_fileName = file.data();
        }
        m_fileNameSize = file.size();

        FormatTime();
        this_thrd::Tid();
        m_strm << '[' << detail::KnownLengthString(this_thrd::TidString(), this_thrd::TidStringLength()) << ']' << " ";
        m_strm << detail::KnownLengthString(detail::LogLevelName[(int)level], 8);
        if (savedErrno != 0)
            m_strm << detail::strerror_tl(savedErrno) << " (errno=" << savedErrno << ") ";
    }
    void Logger::Formatter::FormatTime()
    {
        using namespace detail;
        static KnownLengthString timeString(t_time, 0);
        char* p = nullptr;

        if (m_time.Sec() != t_lastSecond)
        {
            t_lastSecond = m_time.Sec();
            if (!s_isLocalTimeZone)
                p = m_time.GmLogFormat(t_time);
            else
                p = m_time.LocalLogFormat(t_time);
        }

        if (p)
            timeString = KnownLengthString(t_time, p - t_time);

        m_strm << timeString;
    }
    void Logger::Formatter::Finish()
    {
        m_strm << " - " << detail::KnownLengthString(m_fileName, m_fileNameSize) << ':' << m_line << '\n';
    }
    Logger::Logger(const std::string_view& file, int line) : m_fmt(LogLevel::INFO, 0, file, line) {}
    Logger::Logger(const std::string_view& file, int line, LogLevel level, const char* func)
        : m_fmt(level, 0, file, line) { m_fmt.m_strm << func << ' '; }
    Logger::Logger(const std::string_view& file, int line, LogLevel level) : m_fmt(level, 0, file, line) {}
    Logger::Logger(const std::string_view& file, int line, bool toAbort)
        : m_fmt(toAbort ? LogLevel::FATAL : LogLevel::ERROR, errno, file, line) {}
    Logger::~Logger()
    {
        using namespace std::chrono;
        m_fmt.Finish();

        const detail::LogStream::FixedBuf& buf(Stream().Buffer());

        detail::g_output(buf.Data(), buf.Size());

        if (m_fmt.m_level == LogLevel::FATAL)
        {
            detail::g_flush();
            abort();
        }
    }
    Logger::LogLevel Logger::Level() { return detail::g_logLevel; }
    void Logger::SetOutput(void (*out)(const char* msg, const uint64_t len)) { detail::g_output = out; }
    void Logger::SetFlush(void (*flush)()) { detail::g_flush = flush; }



    void SyncLogFile::Append(const char* logline, uint64_t len)
    {
        if (m_mu)
        {
            std::lock_guard locker(*m_mu);
            AppendUnlocked(logline, len);
        }
        else
            AppendUnlocked(logline, len);
    }
    void SyncLogFile::Flush()
    {
        if (m_mu)
        {
            std::lock_guard locker(*m_mu);
            m_appender->Flush();
        }
        else
            m_appender->Flush();
    }
    bool SyncLogFile::Roll()
    {
        auto timestamp = Timestamp();
        time_t now = timestamp.As_time_t();

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
    std::string SyncLogFile::MakeLogFileName(const std::string& basename, const Timestamp& timestamp)
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

        filename += fmt::format(".{}", process::Pid());

        filename += ".log";
        return filename;
    }
    void SyncLogFile::AppendUnlocked(const char* logline, const uint64_t len)
    {
        m_appender->Append(logline, len);

        if (m_appender->WrittenBytes() > (uint64_t)k_RollSize)  //如果写入的大小>rollSize就roll
            Roll();
        else if (++m_count >= k_CheckEveryN)
        {
            m_count = 0;  //如果写入次数>=这个数就重新计数
            time_t now = time(0);
            time_t day = now / k_OneDaySeconds * k_OneDaySeconds;
            if (day != m_day)  //如果过了0点就roll
                Roll();
            else if (now - m_lastFlush > (time_t)k_FlushInterval)  //没过0点就flush
            {
                m_lastFlush = now;
                m_appender->Flush();
            }
        }
    }



    AsyncLogFile::AsyncLogFile(const std::string& basename, int64_t rollSize, bool localTimeZone, int flushInterval)
        : k_flushInterval(flushInterval),
          m_isLocalTimeZone(localTimeZone),
          m_fileName(basename),
          m_rollSize(rollSize),
          m_thrd(std::bind(&AsyncLogFile::Handle, this), "Async Logger"),
          m_thisBuf(std::make_unique<FixedBuf>()),
          m_nextBuf(std::make_unique<FixedBuf>())
    {
        m_thisBuf->Zero();
        m_nextBuf->Zero();
        m_bufs.reserve(16);
        Logger::SetTimeZone(m_isLocalTimeZone);

        m_running = true;
        m_thrd.Start();
        m_latch.Wait();
    }
    AsyncLogFile::~AsyncLogFile()
    {
        if (m_running)
            Stop();
    }
    void AsyncLogFile::Append(const char* logline, uint64_t len)
    {
        std::lock_guard locker(m_mu);
        if (m_thisBuf->AvalibleSize() > len)  //没满
            m_thisBuf->Append(logline, len);
        else  //满了
        {
            m_bufs.push_back(std::move(m_thisBuf));  //将此buf加入待输出的队列

            if (m_nextBuf)
                m_thisBuf = std::move(m_nextBuf);  //拿下一个空的buf
            else
                m_thisBuf.reset(new FixedBuf);  // 没有空buf了就创建一个新的，但几乎不会发生

            m_thisBuf->Append(logline, len);
            m_fullCond.notify_one();  //通知其他线程，buf满了
        }
    }
    void AsyncLogFile::Stop()
    {
        m_running = false;
        m_fullCond.notify_one();
        m_thrd.Join();
    }
    void AsyncLogFile::Handle()
    {
        m_latch.CountDown();
        SyncLogFile logFile(m_fileName, m_rollSize, m_isLocalTimeZone, false);

        //准备两个空的Buf
        BufPtr newBuf1(new FixedBuf);
        BufPtr newBuf2(new FixedBuf);
        newBuf1->Zero();
        newBuf2->Zero();

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
                fmt::format_to(buf, "Discardped log messages at {}, {} larger buffers\n",
                               Timestamp::Now().GmFormatString(), bufVec.size() - 2);
                fputs(buf, stderr);
                logFile.Append(buf, strlen(buf));
                bufVec.erase(bufVec.begin() + 2, bufVec.end());  //处理方法是将buf都舍弃掉，只留下两个，废物利用
            }
            for (auto&& item : bufVec)  //遍历，输出所有要输出的buf
                logFile.Append(item->Data(), item->Size());

            if (bufVec.size() > 2)
                bufVec.resize(2);  // 丢掉所有的buf，留两个是为了给之后newBuf1和newBuf2用，属于废物利用

            if (!newBuf1)  //如果newBuf1被用了就补上
            {
                newBuf1 = std::move(bufVec.back());
                bufVec.pop_back();
                newBuf1->Reset();
            }

            if (!newBuf2)  //如果newBuf2被用了也补上
            {
                newBuf2 = std::move(bufVec.back());
                bufVec.pop_back();
                newBuf2->Reset();
            }

            bufVec.clear();
            logFile.Flush();
        }
        logFile.Flush();
    }



    SockAddr::SockAddr(uint16_t port, const char* host) { detail::IpProtToAddr(port, host, this); }
    std::string SockAddr::ipString() const
    {
        char buf[64] = {0};
        detail::AddrToIp(buf, 64, (SockAddr*)this);
        return buf;
    }
    std::string SockAddr::ipPortString() const
    {
        char buf[64] = {0};
        detail::AddrToIpPort(buf, 64, (SockAddr*)this);
        return buf;
    }
    uint16_t SockAddr::HostPort() const
    {
        if (Famliy() == AF_INET)
            return ntohs(sin.sin_port);
        else
            return ntohs(sin6.sin6_port);
    }
    uint16_t SockAddr::NetPort() const
    {
        if (Famliy() == AF_INET)
            return sin.sin_port;
        else
            return sin6.sin6_port;
    }



    EventLoop::EventLoop()
        : m_wakeUpfd(detail::CreateEventfd()),
          m_threadID(this_thrd::Tid()),
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
        m_runningExtraFuncs.reserve(4);
        m_waitingExtraFuncs.reserve(4);
    }
    EventLoop::~EventLoop()
    {
        LOG_DEBUG << "EventLoop " << this << " of thread " << m_threadID
                  << " destructs in thread " << this_thrd::Tid();
        m_wakeUpChannel->OffAll();
        m_wakeUpChannel->Remove();
        detail::Close(m_wakeUpfd);
        detail::t_loopOfThisThread = nullptr;
    }
    void EventLoop::Loop()
    {
        AssertInLoopThread();
        std::atomic_int32_t n = 0;
        if (m_shutdownInterval != 0)
            m_shutdownTimingWheel = std::make_unique<detail::ShutDownTimingWheel>(this, m_shutdownInterval);
        if (m_heartbeatInterval != 0)
            m_heartbeatTimingWheel = std::make_unique<detail::HeartbeatTimingWheel>(this, m_heartbeatInterval);


        m_looping = true;
        m_quit = false;
        LOG_TRACE << "EventLoop " << this << " start looping";

        while (!m_quit)
        {
            //没事的时候loop会阻塞在这里
            m_returnTime = m_poller->Poll(detail::k_PollTimeoutMs, &m_activeChannels);
            m_loopNum++;

            if (Logger::Level() <= Logger::LogLevel::TRACE)
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
    void EventLoop::Quit()
    {
        m_quit = true;
        if (!InLoopThread())
            Wakeup();
    }
    void EventLoop::Run(std::function<void()> callback)
    {
        if (InLoopThread())
            callback();
        else
            AddExtraFunc(std::move(callback));
    }
    void EventLoop::AddExtraFunc(std::function<void()> callback)
    {
        {
            std::lock_guard lock(m_mu);
            m_waitingExtraFuncs.emplace_back(std::move(callback));
        }

        if (!InLoopThread() || m_runningExtraFunc)
            Wakeup();
    }
    uint64_t EventLoop::GetExtraFuncsNum() const
    {
        std::lock_guard lock(m_mu);
        return m_waitingExtraFuncs.size();
    }
    void EventLoop::Wakeup()
    {
        uint64_t one = 1;
        ssize_t n = write(m_wakeUpfd, &one, sizeof(one));
        if (n != sizeof(one))
            LOG_ERROR << "EventLoop::wakeup() writes " << n << " bytes instead of 8";
    }
    void EventLoop::UpdateChannel(detail::Channel* channel)
    {
        AssertInLoopThread();
        m_poller->UpdateChannel(channel);
    }
    void EventLoop::RemoveChannel(detail::Channel* channel)
    {
        AssertInLoopThread();
        m_poller->RemoveChannel(channel);
    }
    bool EventLoop::HasChannel(detail::Channel* channel)
    {
        AssertInLoopThread();
        return m_poller->HasChannel(channel);
    }
    EventLoop* EventLoop::GetLoopOfThisThread() { return detail::t_loopOfThisThread; }
    void EventLoop::WakeUpRead()
    {
        uint64_t one = 1;
        ssize_t n = read(m_wakeUpfd, &one, sizeof one);
        if (n != sizeof(one))
            LOG_ERROR << "EventLoop::WakeUpRead() reads " << n << " bytes instead of 8";
    }
    void EventLoop::RunExtraFunc()
    {
        if (m_waitingExtraFuncs.empty())
            return;
        else
        {
            m_runningExtraFunc = true;
            std::lock_guard lock(m_mu);
            m_runningExtraFuncs.swap(m_waitingExtraFuncs);
        }
        //既减少了持有锁的时间，也防止了死锁(func里可能也调用了RunExtraFunc()

        for (auto&& func : m_runningExtraFuncs)
            func();
        m_runningExtraFuncs.clear();
        m_runningExtraFunc = false;
    }
    void EventLoop::PrintActiveChannels() const
    {
        for (auto&& channel : m_activeChannels)
            LOG_TRACE << "{" << channel->ReventsString() << "} ";
    }
    void EventLoop::AssertInLoopThread()
    {
        if (!InLoopThread())
            LOG_FATAL << "EventLoop::abortNotInLoopThread - EventLoop " << this
                      << " was created in threadID_ = " << m_threadID
                      << ", current thread id = " << this_thrd::Tid();
    }
    TimerID EventLoop::RunAt(Timestamp time, std::function<void()> callback)
    {
        return timerQueue_->Add(std::move(callback), time, 0.0);
    }
    TimerID EventLoop::RunAfter(double delay, std::function<void()> callback)
    {
        Timestamp time(Timestamp::AddTime(Timestamp::Now(), delay));
        return RunAt(time, std::move(callback));
    }
    TimerID EventLoop::RunEvery(double interval, std::function<void()> callback)
    {
        Timestamp time(Timestamp::AddTime(Timestamp::Now(), interval));
        return timerQueue_->Add(std::move(callback), time, interval);
    }
    void EventLoop::Cancel(TimerID timerID) { return timerQueue_->Cancel(timerID); }
    void EventLoop::AddShutdown(const std::shared_ptr<TcpConnection>& conn)
    {
        m_shutdownTimingWheel->PushAndSetAny(conn);
    }
    void EventLoop::UpdateShutdown(const std::shared_ptr<TcpConnection>& conn)
    {
        m_shutdownTimingWheel->Update(conn);
    }
    void EventLoop::AddHeartbeat(const std::shared_ptr<TcpConnection>& conn) { m_heartbeatTimingWheel->Add(conn); }





    void Buffer::Swap(Buffer& other)
    {
        std::swap(m_buf, other.m_buf);
        std::swap(m_readIndex, other.m_readIndex);
        std::swap(m_writeIndex, other.m_writeIndex);
    }
    void Buffer::Resize(uint64_t new_size)
    {
        m_buf = std::unique_ptr<Buf>((Buf*)realloc(m_buf.release(), sizeof(Buf) + k_PrependSize + new_size));
        m_buf->len = k_PrependSize + new_size;
    }
    const char* Buffer::FindCRLF() const
    {
        const char* crlf = std::search(ReadIndex(), WriteIndex(), k_CRLF, k_CRLF + 2);
        return crlf == WriteIndex() ? NULL : crlf;
    }
    const char* Buffer::FindCRLF(const char* start) const
    {
        const char* crlf = std::search(start, WriteIndex(), k_CRLF, k_CRLF + 2);
        return crlf == WriteIndex() ? NULL : crlf;
    }
    void Buffer::Discard(uint64_t len)
    {
        if (len <= ReadableBytes())
            m_readIndex += len;
        else
            m_readIndex = m_writeIndex = k_PrependSize;
    }
    std::string Buffer::RetrieveAsString(uint64_t len)
    {
        std::string res(ReadIndex(), len);
        Discard(len);
        return res;
    }
    void Buffer::EnsureWritableBytes(uint64_t len)
    {
        if (WriteableBytes() < len)
            MakeSpace(len);
    }
    void Buffer::Append(const char* data, uint64_t len)
    {
        EnsureWritableBytes(len);
        memcpy(WriteIndex(), data, len);
        m_writeIndex += len;
    }
    void Buffer::AppendInt16(int16_t x)
    {
        int16_t n = htons(x);
        Append(&n, sizeof(n));
    }
    void Buffer::AppendInt32(int x)
    {
        int n = htonl(x);
        Append(&n, sizeof(n));
    }
    void Buffer::AppendInt64(int64_t x)
    {
        int64_t n = htonll(x);
        Append(&n, sizeof(n));
    }
    void Buffer::AppendFloat(float x)
    {
        void* p = &x;
        int n = *(int*)p;
        n = htonl(n);
        Append(&n, 4);
    }
    void Buffer::AppendDouble(double x)
    {
        void* p = &x;
        int64_t n = *(int64_t*)p;
        n = htonll(n);
        Append(&n, 8);
    }
    int8_t Buffer::ReadInt8()
    {
        int8_t res = PeekInt8();
        DiscardInt8();
        return res;
    }
    int16_t Buffer::ReadInt16()
    {
        int16_t res = PeekInt16();
        DiscardInt16();
        return res;
    }
    int Buffer::ReadInt32()
    {
        int res = PeekInt32();
        DiscardInt32();
        return res;
    }
    int64_t Buffer::ReadInt64()
    {
        int64_t res = PeekInt64();
        DiscardInt64();
        return res;
    }
    float Buffer::ReadFloat()
    {
        float res = PeekFloat();
        DiscardInt32();
        return res;
    }
    double Buffer::ReadDouble()
    {
        double res = PeekDouble();
        DiscardInt64();
        return res;
    }
    int16_t Buffer::PeekInt16() const
    {
        int16_t n = 0;
        memcpy(&n, ReadIndex(), sizeof(n));
        return ntohs(n);
    }
    int Buffer::PeekInt32() const
    {
        int n = 0;
        memcpy(&n, ReadIndex(), sizeof(n));
        return ntohl(n);
    }
    int64_t Buffer::PeekInt64() const
    {
        int64_t n = 0;
        memcpy(&n, ReadIndex(), sizeof(n));
        return ntohll(n);
    }
    float Buffer::PeekFloat() const
    {
        int n = 0;
        memcpy(&n, ReadIndex(), sizeof(n));
        n = ntohl(n);
        void* p = &n;
        return *(float*)p;
    }
    double Buffer::PeekDouble() const
    {
        int64_t n = 0;
        memcpy(&n, ReadIndex(), sizeof(n));
        n = ntohll(n);
        void* p = &n;
        return *(double*)p;
    }
    void Buffer::Prepend(const void* data, uint64_t len)
    {
        if (m_readIndex < len)
            LOG_FATAL << "in Buffer::prepend   lack of PrependableBytes";
        m_readIndex -= len;
        memcpy((char*)ReadIndex(), (const char*)data, len);
    }
    void Buffer::PrependInt16(int16_t x)
    {
        int16_t n = htons(x);
        Prepend(&n, sizeof(n));
    }
    void Buffer::PrependInt32(int x)
    {
        int n = htonl(x);
        Prepend(&n, sizeof(n));
    }
    void Buffer::PrependInt64(int64_t x)
    {
        int64_t n = htonll(x);
        Prepend(&n, sizeof(n));
    }
    void Buffer::PrependFloat(float x)
    {
        void* p = &x;
        int n = *(int*)p;
        n = htonl(n);
        Prepend(&n, sizeof(n));
    }
    void Buffer::PrependDouble(double x)
    {
        void* p = &x;
        int64_t n = *(int64_t*)p;
        n = htonll(n);
        Prepend(&n, sizeof(n));
    }
    void Buffer::Shrink(uint64_t reserve)
    {
        Buffer other;
        other.EnsureWritableBytes(ReadableBytes() + reserve);
        other.Append(ToStringView());
        Swap(other);
    }
    void Buffer::MakeSpace(uint64_t len)
    {
        if (WriteableBytes() + PrependableBytes() < len + k_PrependSize)
        {
            Resize(m_writeIndex + len);  //不够就开辟一片新的地方
        }
        else  //够就把数据移到最前面,后面就是space
        {
            uint64_t readable = ReadableBytes();
            char* p = Begin();
            memcpy(p + k_PrependSize, p + m_readIndex, readable);
            m_readIndex = k_PrependSize;
            m_writeIndex = m_readIndex + readable;
        }
    }
    ssize_t Buffer::ReadSocket(int fd, int* savedErrno)  //TODO   热点
    {
        char tmpBuf[65535];
        //两个缓冲区，一个是Buffer剩余的空间，一个是tmpbuf
        iovec vec[2];
        const uint64_t writeable = WriteableBytes();
        vec[0].iov_base = WriteIndex();
        vec[0].iov_len = writeable;
        vec[1].iov_base = tmpBuf;
        vec[1].iov_len = sizeof(tmpBuf);

        const ssize_t n = readv(fd, vec, 2);

        //错误
        if (n < 0)
            *savedErrno = errno;

        //Buffer空间够
        else if ((uint64_t)n <= writeable)
            m_writeIndex += n;
        //Buffer空间不够
        else
        {
            m_writeIndex = Capacity();
            Append(tmpBuf, n - writeable);
        }

        return n;
    }





    TcpConnection::TcpConnection(EventLoop* loop, const std::string& name, int sockfd, const SockAddr& localAddr, const SockAddr& peerAddr)
        : m_status(k_Connecting),
          m_loop(loop),
          m_socket(std::make_unique<detail::Socket>(sockfd)),
          m_channel(std::make_unique<detail::Channel>(loop, sockfd)),
          m_localAddr(localAddr),
          m_peerAddr(peerAddr),
          m_name(name)
    {
        m_channel->SetReadCallback(std::bind(&TcpConnection::HandleRead, this, std::placeholders::_1));
        m_channel->SetWriteCallback(std::bind(&TcpConnection::HandleWrite, this));
        m_channel->SetCloseCallback(std::bind(&TcpConnection::HandleClose, this));
        m_channel->SetErrorCallback(std::bind(&TcpConnection::HandleError, this));
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
    void TcpConnection::Send(std::string&& msg)
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
    void TcpConnection::Send(const std::string_view& msg)
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
    void TcpConnection::Send(Buffer* buf)
    {
        if (m_status == k_Connected)
        {
            if (m_loop->InLoopThread())
            {
                SendInLoop(buf->ReadIndex(), buf->ReadableBytes());  //如果是当前线程就直接发送
                buf->DiscardAll();
            }
            else
                //否则放到loop待执行回调队列执行,会发生拷贝
                m_loop->AddExtraFunc(std::bind(&TcpConnection::SendStringView, this, buf->RetrieveAllAsString()));
        }
    }
    void TcpConnection::Shutdown()
    {
        if (m_status == k_Connected)
        {
            m_status = k_Disconnecting;
            m_loop->Run(std::bind(&TcpConnection::ShutdownInLoop, shared_from_this()));
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
            m_loop->RunAfter(seconds, detail::MakeWeakCallback(shared_from_this(), &TcpConnection::ForceClose));
        }
    }
    void TcpConnection::ConnectEstablished()
    {
        m_loop->AssertInLoopThread();
        m_status = k_Connected;
        m_channel->Tie(shared_from_this());  //使Channel生命周期与TcpConnection对象相同
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
        m_channel->Remove();
    }
    void TcpConnection::HandleRead(Timestamp receiveTime)
    {
        m_loop->AssertInLoopThread();
        int savedErrno = 0;
        if (m_inShutdownTimingWheel)
            UpdateShutdownTimingWheel();
        //尝试一次读完tcp缓冲区的所有数据,返回实际读入的字节数(一次可能读不完)
        ssize_t n = m_inputBuf.ReadSocket(m_channel->fd(), &savedErrno);

        if (n > 0)  //读成功就调用用户设置的回调函数
        {
            if (m_decoder.m_lengthFieldLength > 0)
            {
                //分到不能再分为止
                while (m_decoder.IsComplete(&m_inputBuf))  //如果inputBuf中的数据足以构成一个完整的包
                {
                    Buffer buf = m_decoder.Decode(&m_inputBuf);
                    m_msgCallback(shared_from_this(), &buf, receiveTime);
                }
            }
            else
                m_msgCallback(shared_from_this(), &m_inputBuf, receiveTime);
        }
        else if (n == 0)  //说明对方调用了close()
            HandleClose();
        else  //出错
        {
            errno = savedErrno;
            LOG_SYSERR << "TcpConnection::HandleRead";
            HandleError();
        }
    }
    void TcpConnection::HandleWrite()
    {
        m_loop->AssertInLoopThread();
        if (m_channel->IsWriting())
        {
            //尝试一次写完outputBuf的所有数据,返回实际写入的字节数(tcp缓冲区有可能仍然不能容纳所有数据)
            ssize_t n = write(m_channel->fd(), m_outputBuf.ReadIndex(), m_outputBuf.ReadableBytes());
            if (n > 0)
            {
                m_outputBuf.Discard(n);  //调整index
                //如果写完了
                if (m_outputBuf.ReadableBytes() == 0)
                {
                    //不再监听写事件
                    m_channel->OffWriting();
                    //如果设置了写完的回调函数就进行回调
                    if (m_writeCompleteCallback)
                        m_loop->AddExtraFunc(std::bind(m_writeCompleteCallback, shared_from_this()));
                    if (m_status == k_Disconnecting)
                        ShutdownInLoop();
                }
            }
            else
                LOG_SYSERR << "TcpConnection::HandleWrite";
        }
        else
            LOG_TRACE << "Connection fd = " << m_channel->fd() << " is down, no more writing";
    }
    void TcpConnection::HandleClose()
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
    void TcpConnection::HandleError()
    {
        int err = detail::GetSocketError(m_channel->fd());
        LOG_ERROR << "TcpConnection::HandleError [" << m_name << "] - SO_ERROR = " << err << " " << detail::strerror_tl(err);
    }
    void TcpConnection::SendInLoop(const void* data, size_t len)
    {
        m_loop->AssertInLoopThread();
        ssize_t n = 0;
        size_t remain = len;
        bool faultError = false;
        if (m_status == k_Disconnected)
        {
            LOG_WARN << "disconnected, give up writing";
            return;
        }
        //如果没在epoll注册就直接发
        if (!m_channel->IsWriting())
        {
            // aiocb wt;
            // bzero(&wt, sizeof(wt));
            // wt.aio_fildes = m_channel->fd();
            // wt.aio_buf = (char*)data;
            // wt.aio_nbytes = len;
            // wt.aio_offset = 0;
            // wt.aio_lio_opcode = LIO_WRITE;

            // n = aio_write(&wt);

            n = write(m_channel->fd(), data, len);
            if (n >= 0)
            {
                remain = len - n;
                if (m_writeCompleteCallback && remain == 0)  //写完且有回调要执行
                    m_loop->AddExtraFunc(std::bind(m_writeCompleteCallback, shared_from_this()));
            }
            else  //出错,一点也写不进
            {
                n = 0;
                if (errno != EAGAIN)  //如果错误为EAGAIN,表明tcp缓冲区已满
                {
                    LOG_SYSERR << "TcpConnection::SendInLoop";
                    //EPIPE表示客户端已经关闭了连接
                    // ECONNRESET表示连接已重置
                    if (errno == EPIPE || errno == ECONNRESET)
                        faultError = true;
                }
            }
        }

        if (!faultError && remain > 0)  //没出错但没写完(极端情况,tcp缓冲区满了)
        {
            //把剩下的数据写入outputBuf中
            m_outputBuf.Append((const char*)data + n, remain);
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
            HandleClose();
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
    void TcpConnection::AddToShutdownTimingWheel()
    {
        m_inShutdownTimingWheel = true;
        m_loop->AddShutdown(shared_from_this());
    }
    void TcpConnection::UpdateShutdownTimingWheel()
    {
        m_loop->UpdateShutdown(shared_from_this());
    }
    bool TcpConnection::GetTcpInfo(struct tcp_info* tcpi) const { return m_socket->GetTcpInfo(tcpi); }



    TcpServer::TcpServer(EventLoop* loop, const SockAddr& listenAddr, const std::string& name, Option option)
        : m_nextConnID(1),
          m_acceptor(std::make_unique<detail::Acceptor>(loop, listenAddr, option == k_ReusePort)),
          m_loop(loop),
          m_threadPool(std::make_shared<detail::EventLoopThreadPool>(loop, name)),
          m_ipPort(listenAddr.ipPortString()),
          m_name(name),
          m_connCallback(detail::DefaultConnCallback),
          m_msgCallback(detail::DefaultMsgCallback)
    {
        using namespace std::placeholders;
        m_acceptor->SetConnectionCallback(std::bind(&TcpServer::NewConnection, this, _1, _2));
    }
    void TcpServer::Start()
    {
        if (!m_started)
        {
            m_started = true;
            m_threadPool->Start(m_shutdownInterval, m_heartbeatInterval, m_threadInitCallback);
            m_loop->Run(std::bind(&detail::Acceptor::Listen, m_acceptor.get()));
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
            conn->GetLoop()->Run(std::bind(&TcpConnection::ConnectDestroyed, conn));
        }
    }
    void TcpServer::NewConnection(int sockfd, const SockAddr& peerAddr)
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
        conn->SetConnectionCallback(m_connCallback);
        conn->SetMessageCallback(m_msgCallback);
        conn->SetWriteCompleteCallback(m_writeCompleteCallback);
        //关闭回调函数,作用是将这个关闭的TcpConnection从map中删除
        conn->SetCloseCallback(std::bind(&TcpServer::RemoveConnection, this, std::placeholders::_1));
        conn->SetTcpNoDelay(m_tcpNoDelay);
        conn->SetLengthDecoder(&m_decoder);
        if (m_heartbeatInterval != 0)
            ioLoop->AddHeartbeat(conn);
        ioLoop->Run(std::bind(&TcpConnection::ConnectEstablished, std::ref(conn)));
    }
    void TcpServer::RemoveConnection(const std::shared_ptr<TcpConnection>& conn)
    {
        // FIXME 不安全
        //因为调用TcpServer::removeConnection的线程是TcpConnection所在的EventLoop
        //也就是说TcpServer的this指针暴露在TcpConnection所在的EventLoop了
        //如果这个EventLoop对这个this指针做修改,就可能会导致TcpServer出错
        //所以理论上是不安全的,但其实并没有修改,而是立刻进入到TcpServer的EventLoop,所以其实是安全的
        //硬要说不安全,只有下面这一句话理论上不安全(其实也安全),其他全都是安全的
        m_loop->Run(std::bind(&TcpServer::RemoveConnectionInLoop, this, conn));
    }
    void TcpServer::RemoveConnectionInLoop(const std::shared_ptr<TcpConnection>& conn)
    {
        m_loop->AssertInLoopThread();

        // LOG_INFO << "TcpServer::removeConnectionInLoop [" << m_name << "] - connection " << conn->name();
        m_connections.erase(conn->Name());

        //不直接用m_loop->run是因为TcpConnection::ConnectDestroyed应该交给其对应的EventLoop执行
        conn->GetLoop()->AddExtraFunc(std::bind(&TcpConnection::ConnectDestroyed, conn));
        //此时conn引用计数为2
        //1.conn本身   2.上面bind了一个
        //所以离开这个函数后就只剩1,然后执行完TcpConnection::ConnectDestroyed,对应的TcpConnection才真正析构
    }
    void TcpServer::SetHeartbeatMsg(const void* data, int len) { detail::HeartbeatTimingWheel::Msg::SetMsg(data, len); }
    void TcpServer::SetLengthDecoder(int maxFrameLength, int lengthFieldOffset, int lengthFieldLength, int lengthAdjustment, int initialBytesToStrip)
    {
        int len = lengthFieldLength;
        if (len != 1 && len != 2 && len != 4 && len != 8)
            LOG_FATAL << "TcpServer::SetLengthDecoder lengthFieldLength only supports 1/2/4/8";
        m_decoder = LengthDecoder(maxFrameLength, lengthFieldOffset, lengthFieldLength, lengthAdjustment, initialBytesToStrip);
    }

}  // namespace kurisu
