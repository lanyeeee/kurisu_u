#pragma once
namespace kurisu {
    class copyable {
    protected:
        copyable() = default;
        ~copyable() = default;
    };

    class uncopyable {
    protected:
        uncopyable(){};
        ~uncopyable(){};

    private:
        uncopyable(const uncopyable& that);
        uncopyable& operator=(const uncopyable& that);
    };
}  // namespace kurisu