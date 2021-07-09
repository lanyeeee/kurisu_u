#pragma once
#include <exception>
#include "this_thrd.hpp"


namespace kurisu {
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

}  // namespace ava
