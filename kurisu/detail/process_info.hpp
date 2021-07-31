#pragma once
#include <string>
#include <string_view>
#include <fmt/format.h>
#include <pwd.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/resource.h>  //rlimit
#include <sys/times.h>     //tms
#include "../time_stamp.hpp"
#include "string_arg.hpp"
#include "this_thrd.hpp"

namespace kurisu {
    namespace detail {

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


        /// read /proc/self/status
        inline std::string ProcStatus()
        {
            std::string result;
            detail::ReadFile("/proc/self/status", 65536, result);
            return result;
        }

        /// read /proc/self/stat
        inline std::string ProcStat()
        {
            std::string result;
            detail::ReadFile("/proc/self/stat", 65536, result);
            return result;
        }

        /// read /proc/self/task/tid/stat
        inline std::string ThreadStat()
        {
            char buf[64];
            fmt::format_to(buf, "/proc/self/task/{}/stat", this_thrd::tid());
            std::string result;
            detail::ReadFile(buf, 65536, result);
            return result;
        }
        /// readlink /proc/self/exe
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

        struct CpuTime {
            double userSeconds;
            double systemSeconds;

            CpuTime() : userSeconds(0.0), systemSeconds(0.0) {}

            double total() const { return userSeconds + systemSeconds; }
        };
        inline CpuTime cpuTime()
        {
            CpuTime t;
            struct tms tms;
            if (times(&tms) >= 0)
            {
                const double hz = (double)ClockTicksPerSecond();
                t.userSeconds = (double)tms.tms_utime / hz;
                t.systemSeconds = (double)tms.tms_stime / hz;
            }
            return t;
        }

        inline int numThreads()
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
}  // namespace kurisu