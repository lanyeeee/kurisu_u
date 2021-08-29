#include "all.hpp"
#include <iostream>
int main()
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    kurisu::SockAddr addr(5005, "192.168.0.105");
    std::cout << "connect";
    std::cin.get();
    kurisu::detail::Connect(fd, &addr);
    char buf[] = "hahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaahahahaa";
    int n = write(fd, buf, sizeof(buf));
    std::cout << "write" << n << " byte\n";
    bzero(buf, sizeof(buf));
    n = read(fd, buf, sizeof(buf));
    std::cout << "recv:\n"
              << buf << "\n";
    std::cin.get();
    close(fd);
    // kurisu::this_thrd::SleepFor(100000000);
}