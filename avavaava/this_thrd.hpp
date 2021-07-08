#pragma once
#include <string>
#include <string.h>
#include <execinfo.h>
#include <cxxabi.h>
#include <iostream>
#include <sys/syscall.h>
#include <unistd.h>

namespace ava {
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
                t_tidStringLength = snprintf(t_tidString, sizeof(t_tidString), "%5d ", t_cachedTid);
            }
        }
        inline int tid()
        {
            if (t_cachedTid == 0)
                cacheTid();
            return t_cachedTid;
        }
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

    }  // namespace this_thrd
}  // namespace ava