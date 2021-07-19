#pragma once
#include "copyable.hpp"
#include <inttypes.h>
#include <string.h>
#include <string>
#include <string_view>

namespace kurisu {
    namespace detail {

        constexpr uint64_t k_SmallBuf = 4'000;
        constexpr uint64_t k_LargeBuf = 4'000'000;

        template <uint64_t SIZE>
        class FixedBuf : uncopyable {
        public:
            FixedBuf() : m_index(m_data) { m_data[SIZE] = '\0'; }

            uint64_t size() const { return (uint64_t)(m_index - m_data); }
            const char* data() const { return m_data; }
            void IndexMove(uint64_t num) { m_index += num; }
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
    }  // namespace detail
}  // namespace kurisu