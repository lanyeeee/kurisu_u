#pragma once
#include "../event_loop.hpp"
#include "socket.hpp"

namespace kurisu {
    class Acceptor : uncopyable {
    public:
        Acceptor(EventLoop* loop, const SockAddr& listenAddr, bool reuseport);
        ~Acceptor();
        void SetConnectionCallback(const std::function<void(int sockfd, const SockAddr&)>& cb) { m_ConnectionCallback = cb; }
        void listen();
        bool listening() const { return m_listening; }

    private:
        //处理事件
        void HandleRead();

        EventLoop* m_loop;
        Socket m_sock;
        Channel m_channel;
        std::function<void(int sockfd, const SockAddr&)> m_ConnectionCallback;
        bool m_listening;
        int m_voidfd;  //空闲的fd,用于处理fd过多的情况
    };

    inline Acceptor::Acceptor(EventLoop* loop, const SockAddr& listenAddr, bool reuseport)
        : m_loop(loop),
          m_sock(detail::MakeNonblockingSocket(listenAddr.famliy())),
          m_channel(loop, m_sock.fd()),
          m_listening(false),
          m_voidfd(open("/dev/null", O_RDONLY | O_CLOEXEC))  //预先准备一个空闲的fd
    {
        m_sock.SetReuseAddr(true);
        m_sock.SetReusePort(reuseport);
        m_sock.bind((SockAddr*)&listenAddr);
        m_channel.SetReadCallback(std::bind(&Acceptor::HandleRead, this));
    }
    inline Acceptor::~Acceptor()
    {
        m_channel.OffAll();
        m_channel.remove();
        detail::Close(m_voidfd);
    }
    inline void Acceptor::listen()
    {
        m_loop->AssertInLoopThread();
        m_listening = true;
        m_sock.listen();
        m_channel.OnReading();
    }
    inline void Acceptor::HandleRead()
    {
        m_loop->AssertInLoopThread();
        SockAddr peerAddr;

        if (int connfd = m_sock.accept(&peerAddr); connfd >= 0)
        {
            if (m_ConnectionCallback)
                m_ConnectionCallback(connfd, peerAddr);
            else
                detail::Close(connfd);
        }
        else  //FIXME  因为epoll不是ET模式，需要这样来防止因fd过多处理不了而导致epoll繁忙
        {
            LOG_SYSERR << "in Acceptor::handleRead";
            if (errno == EMFILE)  //打开了过多了fd,超过了允许的范围
            {
                detail::Close(m_voidfd);
                m_voidfd = accept(m_sock.fd(), NULL, NULL);
                detail::Close(m_voidfd);
                m_voidfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
            }
        }
    }

}  // namespace kurisu