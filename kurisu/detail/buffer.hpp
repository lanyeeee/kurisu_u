#pragma once
#include <vector>
#include <algorithm>
#include <string>
#include <string_view>
#include <string.h>
#include <inttypes.h>
#include "socket.hpp"
#include "copyable.hpp"

namespace kurisu {
    class Buffer : copyable {
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
        void append(const std::string_view& str) { append(str.data(), str.size()); }
        void append(const void* data, uint64_t len) { append((const char*)data, len); }
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
        // FIXME: use vector::shrink_to_fit() in C++ 11 if possible.
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

    inline ssize_t Buffer::Read(int fd, int* savedErrno)  //TODO   核心代码
    {
        // saved an ioctl()/FIONREAD call to tell how much to read
        char tmpBuf[65536];
        iovec vec[2];
        const uint64_t writable = WritableBytes();
        vec[0].iov_base = begin() + m_writeIndex;
        vec[0].iov_len = writable;
        vec[1].iov_base = tmpBuf;
        vec[1].iov_len = sizeof(tmpBuf);

        const int iovcnt = (writable < sizeof(tmpBuf)) ? 2 : 1;
        const ssize_t n = detail::Readv(fd, vec, iovcnt);
        if (n < 0)
            *savedErrno = errno;
        else if ((uint64_t)n <= writable)
            m_writeIndex += n;
        else
        {
            m_writeIndex = m_vec.size();
            append(tmpBuf, n - writable);
        }
        return n;
    }



}  // namespace kurisu