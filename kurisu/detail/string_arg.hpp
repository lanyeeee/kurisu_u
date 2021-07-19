#pragma once
#include <string>
#include <string_view>

namespace kurisu {
    class StringArg  // copyable
    {
    public:
        StringArg(const char* str) : m_str(str) {}
        StringArg(const std::string& str) : m_str(str.c_str()) {}
        StringArg(const std::string_view& str) : m_str(str.data()) {}
        const char* c_str() const { return m_str; }

    private:
        const char* m_str;
    };
}  // namespace kurisu