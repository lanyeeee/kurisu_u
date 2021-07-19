#pragma once
#include <inttypes.h>

class KnownLengthString {
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
