#pragma once
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>  // readv
#include <sys/timerfd.h>
#include <netinet/tcp.h>  //tcp_info
#include <unistd.h>
#include <netdb.h>  //addrinfo
#include <fmt/format.h>
#include "../log.hpp"


inline uint64_t htonll(uint64_t val) { return htobe64(val); }
inline uint64_t ntohll(uint64_t val) { return be64toh(val); }

namespace kurisu {

    class SockAddr : copyable {
    public:
        SockAddr() = default;
        explicit SockAddr(uint16_t port, const char* host = "0.0.0.0");
        explicit SockAddr(const sockaddr& addr) : sa(addr) {}
        explicit SockAddr(const sockaddr_in& addr) : sin(addr) {}
        explicit SockAddr(const sockaddr_in6& addr) : sin6(addr) {}

        sockaddr& as_sockaddr() { return sa; }
        sockaddr_in& as_sockaddr_in() { return sin; }
        sockaddr_in6& as_sockaddr_in6() { return sin6; }

        sa_family_t famliy() const { return sa.sa_family; }
        std::string ipString() const;
        std::string ipPortString() const;
        uint16_t HostPort() const;
        uint16_t NetPort() const;

        void SetScopeID(uint32_t scope_id) { sin6.sin6_scope_id = scope_id; }

    private:
        union {
            sockaddr sa;
            sockaddr_in sin;
            sockaddr_in6 sin6;
        };
    };



    namespace detail {
        inline socklen_t SizeofSockAddr(SockAddr* addr)
        {
            if (addr->famliy() == AF_INET)
                return sizeof(struct sockaddr_in);
            else
                return sizeof(struct sockaddr_in6);
        }

        inline int MakeNonblockingSocket(sa_family_t family)
        {
            int sockfd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
            if (sockfd < 0)
                LOG_SYSFATAL << "Socket::MakeNonblockingSocket";
            return sockfd;
        }
        inline int Connect(int sockfd, SockAddr* addr) { return connect(sockfd, &addr->as_sockaddr(), SizeofSockAddr(addr)); }
        inline void Bind(int sockfd, SockAddr* addr)
        {
            if (int res = bind(sockfd, &addr->as_sockaddr(), SizeofSockAddr(addr)); res < 0)
                LOG_SYSFATAL << "Socket::BindAndListen  bind";
        }
        inline void Listen(int sockfd)
        {
            if (int res = listen(sockfd, SOMAXCONN); res < 0)
                LOG_SYSFATAL << "Socket::BindAndListen  listen";
        }
        inline int Accept(int sockfd, SockAddr* addr)
        {
            socklen_t addrlen = sizeof(*addr);

            //将fd直接设为非阻塞
            //FIXME  IPv6可以吗
            int connfd = accept4(sockfd, &addr->as_sockaddr(), &addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (connfd < 0)
            {
                int savedErrno = errno;
                LOG_SYSERR << "Socket::Accept";
                switch (savedErrno)
                {
                    case EAGAIN:
                    case ECONNABORTED:
                    case EINTR:
                    case EPROTO:  // ???
                    case EPERM:
                    case EMFILE:  // per-process lmit of open file desctiptor ???
                        // expected errors
                        errno = savedErrno;
                        break;
                    case EBADF:
                    case EFAULT:
                    case EINVAL:
                    case ENFILE:
                    case ENOBUFS:
                    case ENOMEM:
                    case ENOTSOCK:
                    case EOPNOTSUPP:
                        // unexpected errors
                        LOG_FATAL << "unexpected error of ::accept " << savedErrno;
                        break;
                    default:
                        LOG_FATAL << "unknown error of ::accept " << savedErrno;
                        break;
                }
            }
            return connfd;
        }

        inline ssize_t Read(int sockfd, void* buf, uint64_t count) { return read(sockfd, buf, count); }

        inline ssize_t Readv(int sockfd, const struct iovec* iov, int iovcnt) { return readv(sockfd, iov, iovcnt); }

        inline ssize_t Write(int sockfd, const void* buf, uint64_t count) { return write(sockfd, buf, count); }

        inline void Close(int sockfd)
        {
            if (close(sockfd) < 0)
                LOG_SYSERR << "Sockets::Close";
        }

        inline void ShutdownWrite(int sockfd)
        {
            if (shutdown(sockfd, SHUT_WR) < 0)
                LOG_SYSERR << "Sockets::ShutdownWrite";
        }

        inline void IpProtToAddr(uint16_t port, const char* host, SockAddr* addr)
        {
            // addr->sin_port = htons(port);
            sockaddr_in& sin = addr->as_sockaddr_in();
            sockaddr_in6& sin6 = addr->as_sockaddr_in6();

            if (inet_pton(AF_INET, host, &sin.sin_addr) == 1)  //IPv4
                sin.sin_family = AF_INET;
            else if (inet_pton(AF_INET6, host, &sin6.sin6_addr) == 1)  //IPv6
                sin6.sin6_family = AF_INET6;
            else  //host
            {
                addrinfo* ais = NULL;
                int ret = getaddrinfo(host, NULL, NULL, &ais);
                if (ret != 0 || ais == NULL || ais->ai_addrlen == 0 || ais->ai_addr == NULL)
                {
                    LOG_SYSERR << "Socket::IpProtToAddr host resolve";
                    return;
                }
                memcpy(&addr->as_sockaddr(), ais->ai_addr, ais->ai_addrlen);
                freeaddrinfo(ais);
            }
            if (addr->famliy() == AF_INET)
                sin.sin_port = htons(port);
            else
                sin6.sin6_port = htons(port);
        }

        inline void AddrToIp(char* buf, uint64_t size, SockAddr* addr)
        {
            if (addr->famliy() == AF_INET)
                inet_ntop(AF_INET, &addr->as_sockaddr_in().sin_addr, buf, (socklen_t)size);
            else if (addr->famliy() == AF_INET6)
                inet_ntop(AF_INET6, &addr->as_sockaddr_in6().sin6_addr, buf, (socklen_t)size);
        }

        inline void AddrToIpPort(char* buf, uint64_t size, SockAddr* addr)
        {
            if (addr->famliy() == AF_INET)
            {
                AddrToIp(buf, size, addr);
                uint64_t end = strlen(buf);
                uint16_t port = addr->HostPort();
                // snprintf(buf + end, size - end, ":%u", port);
                fmt::format_to(buf + end, ":{}", port);
            }
            else
            {
                buf[0] = '[';
                AddrToIp(buf + 1, size - 1, addr);
                uint64_t end = strlen(buf);
                uint16_t port = addr->HostPort();
                // snprintf(buf + end, size - end, "]:%u", port);
                fmt::format_to(buf + end, "]:{}", port);
            }
        }

        inline int GetSocketError(int sockfd)
        {
            int optval;
            socklen_t optlen = sizeof(optval);

            if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) < 0)
                return errno;
            else
                return optval;
        }

        inline SockAddr GetLocalAddr(int sockfd)
        {
            SockAddr localaddr;
            memset(&localaddr, 0, sizeof(SockAddr));
            socklen_t addrlen = sizeof(SockAddr);
            if (getsockname(sockfd, &localaddr.as_sockaddr(), &addrlen) < 0)
                LOG_SYSERR << "Sockets::GetLocalAddr";
            return localaddr;
        }
        inline SockAddr GetPeerAddr(int sockfd)
        {
            SockAddr peeraddr;
            memset(&peeraddr, 0, sizeof(SockAddr));
            socklen_t addrlen = sizeof(SockAddr);
            if (getpeername(sockfd, &peeraddr.as_sockaddr(), &addrlen) < 0)
                LOG_SYSERR << "Sockets::GetPeerAddr";
            return peeraddr;
        }


        //FIXME   待测试
        inline bool IsSelfConnect(int sockfd)
        {
            SockAddr localaddr = GetLocalAddr(sockfd);
            SockAddr peeraddr = GetPeerAddr(sockfd);
            if (localaddr.famliy() == AF_INET)
            {
                sockaddr_in& local = localaddr.as_sockaddr_in();
                sockaddr_in& peer = peeraddr.as_sockaddr_in();
                return local.sin_port == peer.sin_port && local.sin_addr.s_addr == peer.sin_addr.s_addr;
            }
            else if (localaddr.famliy() == AF_INET6)
            {
                sockaddr_in6& local = localaddr.as_sockaddr_in6();
                sockaddr_in6& peer = peeraddr.as_sockaddr_in6();
                return local.sin6_port == peer.sin6_port &&
                       memcmp(&local.sin6_addr, &peer.sin6_addr, sizeof(local.sin6_addr)) == 0;
            }
            else
                return false;
        }

        inline int MakeNonblockingTimerfd()
        {
            int timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
            if (timerfd < 0)
                LOG_SYSFATAL << "Failed in MakeNonblockingTimerfd";
            return timerfd;
        }

        inline timespec HowMuchTimeFromNow(Timestamp when)
        {
            Timestamp now;
            int64_t ns = when.nsSinceEpoch() - now.nsSinceEpoch();
            timespec ts;
            ts.tv_sec = (time_t)(ns / 1'000'000'000);
            ts.tv_nsec = ns % 1'000'000'000;
            return ts;
        }

        inline int ResetTimerfd(int timerfd, Timestamp runtime)
        {
            itimerspec newValue;
            itimerspec oldValue;
            memset(&newValue, 0, sizeof(newValue));
            memset(&oldValue, 0, sizeof(oldValue));
            newValue.it_value = HowMuchTimeFromNow(runtime);

            return timerfd_settime(timerfd, 0, &newValue, &oldValue);
        }



    }  // namespace detail



    inline SockAddr::SockAddr(uint16_t port, const char* host) { detail::IpProtToAddr(port, host, this); }
    inline std::string SockAddr::ipString() const
    {
        char buf[64] = {0};
        detail::AddrToIp(buf, 64, (SockAddr*)this);
        return buf;
    }
    inline std::string SockAddr::ipPortString() const
    {
        char buf[64] = {0};
        detail::AddrToIpPort(buf, 64, (SockAddr*)this);
        return buf;
    }
    inline uint16_t SockAddr::HostPort() const
    {
        if (famliy() == AF_INET)
            return ntohs(sin.sin_port);
        else
            return ntohs(sin6.sin6_port);
    }
    inline uint16_t SockAddr::NetPort() const
    {
        if (famliy() == AF_INET)
            return sin.sin_port;
        else
            return sin6.sin6_port;
    }





    class Socket : uncopyable {
    public:
        explicit Socket(int sockfd) : m_fd(sockfd) {}

        // Socket(Socket&&) // move constructor in C++11
        ~Socket() { detail::Close(m_fd); }

        int fd() const { return m_fd; }
        // return true if success.
        bool GetTcpInfo(struct tcp_info*) const;
        bool GetTcpInfoString(char* buf) const;

        /// abort if address in use
        void bind(SockAddr* addr) { detail::Bind(m_fd, addr); }
        /// abort if address in use
        void listen() { detail::Listen(m_fd); }

        /// On success, returns a non-negative integer that is
        /// a descriptor for the accepted socket, which has been
        /// set to non-blocking and close-on-exec. *peeraddr is assigned.
        /// On error, -1 is returned, and *peeraddr is untouched.
        int accept(SockAddr* peeraddr) { return detail::Accept(m_fd, peeraddr); }

        void ShutdownWrite() { detail::ShutdownWrite(m_fd); }

        /// Enable/disable TCP_NODELAY (disable/enable Nagle's algorithm).
        void SetTcpNoDelay(bool on);

        /// Enable/disable SO_REUSEADDR
        void SetReuseAddr(bool on);

        /// Enable/disable SO_REUSEPORT
        void SetReusePort(bool on);

        /// Enable/disable SO_KEEPALIVE
        // void setKeepAlive(bool on);

    private:
        const int m_fd;
    };

    inline bool Socket::GetTcpInfo(tcp_info* tcpi) const
    {
        socklen_t len = sizeof(*tcpi);
        memset(tcpi, 0, len);
        return getsockopt(m_fd, SOL_TCP, TCP_INFO, tcpi, &len) == 0;
    }
    inline bool Socket::GetTcpInfoString(char* buf) const
    {
        tcp_info tcpi;
        bool ok = GetTcpInfo(&tcpi);
        if (ok)
        {
            fmt::format_to(buf, "unrecovered={} "
                                "rto={} ato={} snd_mss={} rcv_mss={} "
                                "lost={} retrans={} rtt={} rttvar={} "
                                "sshthresh={} cwnd={} total_retrans={}",
                           tcpi.tcpi_retransmits,  // Number of unrecovered [RTO] timeouts
                           tcpi.tcpi_rto,          // Retransmit timeout in usec
                           tcpi.tcpi_ato,          // Predicted tick of soft clock in usec
                           tcpi.tcpi_snd_mss,
                           tcpi.tcpi_rcv_mss,
                           tcpi.tcpi_lost,     // Lost packets
                           tcpi.tcpi_retrans,  // Retransmitted packets out
                           tcpi.tcpi_rtt,      // Smoothed round trip time in usec
                           tcpi.tcpi_rttvar,   // Medium deviation
                           tcpi.tcpi_snd_ssthresh,
                           tcpi.tcpi_snd_cwnd,
                           tcpi.tcpi_total_retrans);  // Total retransmits for entire connection
        }
        return ok;
    }
    inline void Socket::SetTcpNoDelay(bool on)
    {
        int optval = on ? 1 : 0;
        setsockopt(m_fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
    }
    inline void Socket::SetReuseAddr(bool on)
    {
        int optval = on ? 1 : 0;
        setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    }
    inline void Socket::SetReusePort(bool on)
    {
#ifdef SO_REUSEPORT
        int optval = on ? 1 : 0;
        int ret = setsockopt(m_fd, SOL_SOCKET, SO_REUSEPORT,
                             &optval, sizeof(optval));
        if (ret < 0 && on)
        {
            LOG_SYSERR << "SO_REUSEPORT failed.";
        }
#else
        if (on)
        {
            LOG_ERROR << "SO_REUSEPORT is not supported.";
        }
#endif
    }



}  // namespace kurisu
