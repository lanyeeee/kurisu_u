#include "all.hpp"
#include <iostream>
int main()
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    kurisu::SockAddr addr(5005);
    std::cout << "connect";
    std::cin.get();
    kurisu::detail::Connect(fd, &addr);
    char buf[] = "hahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaa";
    int n = write(fd, buf, sizeof(buf));
    std::cout << "write" << n << " byte\n";
    while (1)
    {
        bzero(buf, sizeof(buf));
        n = read(fd, buf, sizeof(buf));
        std::cout << "recv " << n << "byte\n";
        if (n == 0)
            break;
    }
    close(fd);
    // kurisu::this_thrd::SleepFor(100000000);
}