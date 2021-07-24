#pragma once
#include <string.h>
#include <memory>

namespace kurisu {
    template <typename To, typename From>
    inline To* down_cast(From* f)
    {
        return (To*)f;
    }

    template <typename To, typename From>
    inline ::std::shared_ptr<To> down_pointer_cast(const ::std::shared_ptr<From>& f)
    {
        return ::std::static_pointer_cast<To>(f);
    }
}  // namespace kurisu