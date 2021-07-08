#pragma once
namespace ava {
    class copyable {
    protected:
        copyable() = default;
        ~copyable() = default;
    };

    class nocopyable {
    protected:
        nocopyable(){};
        ~nocopyable(){};

    private:
        nocopyable(const nocopyable& that);
        nocopyable& operator=(const nocopyable& that);
    };
}  // namespace ava