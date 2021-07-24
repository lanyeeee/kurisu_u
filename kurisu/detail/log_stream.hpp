#pragma once
#include "copyable.hpp"
#include "fixed_buf.hpp"
#include <fmt/format.h>
#include <fmt/compile.h>
#include <algorithm>
#include "known_length_string.hpp"


namespace kurisu {
    namespace detail {
        template <typename T>
        inline uint64_t convert(char buf[], T value)
        {
            static const char digits[] = "9876543210123456789";
            static const char* zero = digits + 9;
            T i = value;
            char* p = buf;

            do
            {
                int lsd = static_cast<int>(i % 10);
                i /= 10;
                *p++ = zero[lsd];
            } while (i != 0);

            if (value < 0)
                *p++ = '-';

            *p = '\0';
            std::reverse(buf, p);

            return p - buf;
        }

        inline uint64_t convertHex(char buf[], uintptr_t value)
        {
            static const char digitsHex[] = "0123456789ABCDEF";
            uintptr_t i = value;
            char* p = buf;

            do
            {
                int lsd = static_cast<int>(i % 16);
                i /= 16;
                *p++ = digitsHex[lsd];
            } while (i != 0);

            *p = '\0';
            std::reverse(buf, p);

            return p - buf;
        }

    }  // namespace detail

    class LogStream : uncopyable {
    public:
        using Buf = detail::FixedBuf<detail::k_SmallBuf>;

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
        LogStream& operator<<(const KnownLengthString& str);

    private:
        template <class T>
        void FormatInt(T val);

    private:
        Buf m_buf;
        static const int k_MaxSize = 32;
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
            m_buf.IndexMove(len);
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
            m_buf.IndexMove(len + 2);
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
    inline LogStream& LogStream::operator<<(const KnownLengthString& str)
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
            m_buf.IndexMove(len);
        }
    }

}  // namespace kurisu