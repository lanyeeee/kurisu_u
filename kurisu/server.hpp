#pragma once
#include "detail/acceptor.hpp"
#include "event_loop.hpp"
#include "detail/buffer.hpp"
#include <atomic>
#include <map>

namespace kurisu {
    namespace detail {
        template <typename CLASS, typename... ARGS>
        class WeakCallback {
        public:
            WeakCallback(const std::weak_ptr<CLASS>& obj, const std::function<void(CLASS*, ARGS...)>& func)
                : m_obj(obj), m_func(func) {}
            void operator()(ARGS&&... args) const
            {
                std::shared_ptr<CLASS> ptr(m_obj.lock());
                if (ptr)
                    m_func(ptr.get(), std::forward<ARGS>(args)...);
            }

        private:
            std::weak_ptr<CLASS> m_obj;
            std::function<void(CLASS*, ARGS...)> m_func;
        };

        template <typename CLASS, typename... ARGS>
        WeakCallback<CLASS, ARGS...> MakeWeakCallback(const std::shared_ptr<CLASS>& object, void (CLASS::*function)(ARGS...))
        {
            return WeakCallback<CLASS, ARGS...>(object, function);
        }

        template <typename CLASS, typename... ARGS>
        WeakCallback<CLASS, ARGS...> MakeWeakCallback(const std::shared_ptr<CLASS>& object, void (CLASS::*function)(ARGS...) const)
        {
            return WeakCallback<CLASS, ARGS...>(object, function);
        }

    }  // namespace detail

    class TcpConnection : uncopyable, public std::enable_shared_from_this<TcpConnection> {
    public:
        TcpConnection(EventLoop* loop, const std::string& name, int sockfd, const SockAddr& localAddr, const SockAddr& peerAddr);
        ~TcpConnection();
        //获取所在的EventLoop
        EventLoop* GetLoop() const { return m_loop; }
        //获取名称
        const std::string& name() const { return m_name; }
        //本地地址
        const SockAddr& LocalAddr() const { return m_localAddr; }
        //远端地址
        const SockAddr& PeerAddr() const { return m_peerAddr; }
        //是否已连接
        bool connected() const { return m_status == k_Connected; }
        //是否已断开连接
        bool disconnected() const { return m_status == k_Disconnected; }
        // return true if success.
        bool GetTcpInfo(struct tcp_info* tcpi) const { return m_socket->GetTcpInfo(tcpi); }
        std::string GetTcpInfoString() const;

        void send(std::string&& msg);  // C++11
        void send(const void* data, int len) { send(std::string_view((const char*)data, len)); }
        void send(const std::string_view& msg);
        void send(Buffer* buf);
        //线程不安全,不能跨线程调用
        void shutdown();

        void ForceClose();
        void ForceCloseWithDelay(double seconds);
        //设置TcpNoDelay
        void SetTcpNoDelay(bool on);

        void startRead() { m_loop->run(std::bind(&TcpConnection::StartReadInLoop, this)); }
        void stopRead() { m_loop->run(std::bind(&TcpConnection::StopReadInLoop, this)); }
        //线程不安全
        bool isReading() const { return m_reading; }
        //连接建立 销毁 产生关闭事件时 都会调用这个回调函数
        void setConnectionCallback(const std::function<void(const std::shared_ptr<TcpConnection>&)>& callback) { m_connCallback = callback; }
        //接收到数据之后会调用这个回调函数
        void setMessageCallback(const std::function<void(const std::shared_ptr<TcpConnection>&, Buffer*, Timestamp)>& callback)
        {
            m_msgCallback = callback;
        }
        //写操作完成时会调用这个回调函数
        void setWriteCompleteCallback(const std::function<void(const std::shared_ptr<TcpConnection>&)>& callback)
        {
            m_writeDoneCallback = callback;
        }
        //应用层缓冲区堆积的数据大于m_highWaterMark时调用
        void setHighWaterMarkCallback(const std::function<void(const std::shared_ptr<TcpConnection>&, uint64_t)>& callback, uint64_t highWaterMark)
        {
            m_highWaterMarkCallback = callback;
            m_highWaterMark = highWaterMark;
        }

        Buffer* inputBuffer() { return &m_inputBuf; }
        Buffer* outputBuffer() { return &m_outputBuf; }

        void setCloseCallback(const std::function<void(const std::shared_ptr<TcpConnection>&)>& callback)
        {
            m_closeCallback = callback;
        }

        //当TcpServer accept一个连接时会调用这个函数
        void ConnectEstablished();
        //当TcpServer remove一个连接或自身析构时会调用这个函数
        void ConnectDestroyed();

    private:
        void handleRead(Timestamp receiveTime);
        void handleWrite();
        void handleClose();
        void handleError();
        void SendStringView(const std::string_view& msg) { SendInLoop(msg.data(), msg.size()); }
        void SendInLoop(const void* message, uint64_t len);
        void ShutdownInLoop();
        void ForceCloseInLoop();
        const char* StatusToString() const;
        void StartReadInLoop();
        void StopReadInLoop();

    private:
        static const int k_Disconnected = 0;
        static const int k_Connecting = 1;
        static const int k_Connected = 2;
        static const int k_Disconnecting = 3;

        EventLoop* m_loop;         //所属的EventLoop
        uint64_t m_highWaterMark;  //应用层缓冲区堆积的数据大于这个数(byte)就回调m_highWaterMarkCallback
        const std::string m_name;  //名称
        std::atomic_int m_status;  //连接的状态
        bool m_reading;            //是否正在read
        std::unique_ptr<Socket> m_socket;
        std::unique_ptr<Channel> m_channel;
        const SockAddr m_localAddr;  //本地地址
        const SockAddr m_peerAddr;   //对端地址
        std::function<void(const std::shared_ptr<TcpConnection>&)> m_connCallback;
        std::function<void(const std::shared_ptr<TcpConnection>&, Buffer*, Timestamp)> m_msgCallback;
        std::function<void(const std::shared_ptr<TcpConnection>&)> m_writeDoneCallback;
        std::function<void(const std::shared_ptr<TcpConnection>&, uint64_t)> m_highWaterMarkCallback;
        std::function<void(const std::shared_ptr<TcpConnection>&)> m_closeCallback;
        Buffer m_inputBuf;
        Buffer m_outputBuf;
    };


    TcpConnection::TcpConnection(EventLoop* loop, const std::string& name, int sockfd, const SockAddr& localAddr, const SockAddr& peerAddr)
        : m_loop(loop),
          m_highWaterMark(64 * 1024 * 1024),
          m_name(name),
          m_status(k_Connecting),
          m_reading(true),
          m_socket(std::make_unique<Socket>(sockfd)),
          m_channel(std::make_unique<Channel>(loop, sockfd)),
          m_localAddr(localAddr),
          m_peerAddr(peerAddr)
    {
        m_channel->SetReadCallback(std::bind(&TcpConnection::handleRead, this, std::placeholders::_1));
        m_channel->SetWriteCallback(std::bind(&TcpConnection::handleWrite, this));
        m_channel->SetCloseCallback(std::bind(&TcpConnection::handleClose, this));
        m_channel->SetErrorCallback(std::bind(&TcpConnection::handleError, this));
        LOG_DEBUG << "TcpConnection::ctor[" << m_name << "] at " << this << " fd=" << sockfd;
    }
    TcpConnection::~TcpConnection()
    {
        LOG_DEBUG << "TcpConnection::~TcpConnection [" << m_name << "] at " << this
                  << " fd=" << m_channel->fd()
                  << " state=" << StatusToString();
    }
    std::string TcpConnection::GetTcpInfoString() const
    {
        char buf[1024];
        buf[0] = '\0';
        m_socket->GetTcpInfoString(buf);
        return buf;
    }
    void TcpConnection::send(std::string&& msg)
    {
        if (m_status == k_Connected)
        {
            if (m_loop->InLoopThread())
                SendInLoop(msg.data(), msg.size());  //如果是当前线程就直接发送
            else
                //否则放到loop待执行回调队列执行,会发生拷贝
                m_loop->AddExtraFunc(std::bind(&TcpConnection::SendStringView, this, msg));
        }
    }
    void TcpConnection::send(const std::string_view& msg)
    {
        if (m_status == k_Connected)
        {
            if (m_loop->InLoopThread())
                SendInLoop(msg.data(), msg.size());  //如果是当前线程就直接发送
            else
                //否则放到loop待执行回调队列执行,会发生拷贝
                m_loop->AddExtraFunc(std::bind(&TcpConnection::SendStringView, this, std::string(msg)));
        }
    }
    void TcpConnection::send(Buffer* buf)
    {
        if (m_status == k_Connected)
        {
            if (m_loop->InLoopThread())
            {
                SendInLoop(buf->BeginRead(), buf->ReadableBytes());  //如果是当前线程就直接发送
                buf->DropAll();
            }
            else
                //否则放到loop待执行回调队列执行,会发生拷贝
                m_loop->AddExtraFunc(std::bind(&TcpConnection::SendStringView, this, buf->RetrieveAllAsString()));
        }
    }
    void TcpConnection::shutdown()
    {
        if (m_status == k_Connected)
        {
            m_status = k_Disconnecting;
            m_loop->run(std::bind(&TcpConnection::ShutdownInLoop, shared_from_this()));
        }
    }
    void TcpConnection::ForceClose()
    {
        if (m_status == k_Connected || m_status == k_Disconnecting)
        {
            m_status = k_Disconnecting;
            m_loop->AddExtraFunc(std::bind(&TcpConnection::ForceCloseInLoop, shared_from_this()));
        }
    }
    void TcpConnection::ForceCloseWithDelay(double seconds)
    {
        if (m_status == k_Connected || m_status == k_Disconnecting)
        {
            m_status = k_Disconnecting;
            m_loop->runAfter(seconds, detail::MakeWeakCallback(shared_from_this(), &TcpConnection::ForceClose));
        }
    }
    void TcpConnection::ConnectEstablished()
    {
        m_loop->AssertInLoopThread();
        m_status = k_Connected;
        m_channel->tie(shared_from_this());  //使Channel生命周期与TcpConnection对象相同
        m_channel->OnReading();              //将channel添加到Poller中
        m_connCallback(shared_from_this());  //调用用户注册的回调函数
    }
    void TcpConnection::ConnectDestroyed()
    {
        m_loop->AssertInLoopThread();
        if (m_status == k_Connected)
        {
            m_status = k_Disconnected;
            m_channel->OffAll();
            m_connCallback(shared_from_this());
        }
        m_channel->remove();
    }
    void TcpConnection::handleRead(Timestamp receiveTime)
    {
        m_loop->AssertInLoopThread();
        int savedErrno = 0;
        //尝试一次读完tcp缓冲区的所有数据,返回实际读入的字节数(一次可能读不完)
        ssize_t n = m_inputBuf.Read(m_channel->fd(), &savedErrno);
        if (n > 0)  //读成功就调用用户设置的回调函数
            m_msgCallback(shared_from_this(), &m_inputBuf, receiveTime);
        else if (n == 0)  //说明对方调用了close()
            handleClose();
        else  //出错
        {
            errno = savedErrno;
            LOG_SYSERR << "TcpConnection::handleRead";
            handleError();
        }
    }
    void TcpConnection::handleWrite()
    {
        m_loop->AssertInLoopThread();
        if (m_channel->IsWriting())
        {
            //尝试一次写完outputBuf的所有数据,返回实际写入的字节数(tcp缓冲区很有可能仍然不能容纳所有数据)
            ssize_t n = detail::Write(m_channel->fd(), m_outputBuf.BeginRead(), m_outputBuf.ReadableBytes());
            if (n > 0)
            {
                m_outputBuf.drop(n);  //调整index
                //如果写完了
                if (m_outputBuf.ReadableBytes() == 0)
                {
                    //不再监听写事件
                    m_channel->OffWriting();
                    //如果设置了写完的回调函数就进行回调
                    if (m_writeDoneCallback)
                        m_loop->AddExtraFunc(std::bind(m_writeDoneCallback, shared_from_this()));
                    if (m_status == k_Disconnecting)
                        ShutdownInLoop();
                }
            }
            else
                LOG_SYSERR << "TcpConnection::handleWrite";
        }
        else
            LOG_TRACE << "Connection fd = " << m_channel->fd() << " is down, no more writing";
    }
    void TcpConnection::handleClose()
    {
        m_loop->AssertInLoopThread();
        LOG_TRACE << "fd = " << m_channel->fd() << " state = " << StatusToString();
        m_status = k_Disconnected;
        m_channel->OffAll();

        std::shared_ptr<TcpConnection> guard = shared_from_this();
        // 此时当前的TcpConnection的引用计数为3
        //1.guard  2.在TcpServer的map中 3.在Channel的tie中(保证Channel回调时TcpConnection还活着)

        m_connCallback(guard);
        m_closeCallback(guard);
    }
    void TcpConnection::handleError()
    {
        int err = detail::GetSocketError(m_channel->fd());
        LOG_ERROR << "TcpConnection::handleError [" << m_name << "] - SO_ERROR = " << err << " " << detail::strerror_tl(err);
    }
    void TcpConnection::SendInLoop(const void* data, size_t len)
    {
        m_loop->AssertInLoopThread();
        ssize_t nwrote = 0;
        size_t remain = len;
        bool faultError = false;
        if (m_status == k_Disconnected)
        {
            LOG_WARN << "disconnected, give up writing";
            return;
        }

        //如果channel没在写数据且outputBuf为空,就直接往fd写
        //因为如果outputBuf不为空就直接往fd写,就会导致顺序出错,应先把outputBuf里的数据发完
        if (!m_channel->IsWriting() && m_outputBuf.ReadableBytes() == 0)
        {
            nwrote = detail::Write(m_channel->fd(), data, len);
            if (nwrote >= 0)
            {
                remain = len - nwrote;
                if (remain == 0 && m_writeDoneCallback)  //写完且有回调要执行
                    m_loop->AddExtraFunc(std::bind(m_writeDoneCallback, shared_from_this()));
            }
            else  //出错,一点也写不进
            {
                nwrote = 0;
                if (errno != EWOULDBLOCK)  //如果错误为EWOULDBLOCK,表明tcp缓冲区已满
                {
                    LOG_SYSERR << "TcpConnection::SendInLoop";
                    //EPIPE表示客户端已经关闭了连接
                    // ECONNRESET表示连接已重置
                    if (errno == EPIPE || errno == ECONNRESET)
                        faultError = true;
                }
            }
        }

        if (!faultError && remain > 0)  //没出错但没写完
        {
            uint64_t bufRemain = m_outputBuf.ReadableBytes();
            //到达阈值且设置了对应的回调函数,则进行回调
            if (bufRemain + remain >= m_highWaterMark && bufRemain < m_highWaterMark && m_highWaterMarkCallback)
                m_loop->AddExtraFunc(std::bind(m_highWaterMarkCallback, shared_from_this(), bufRemain + remain));
            //把剩下的数据写入outputBuf中
            m_outputBuf.append((const char*)data + nwrote, remain);
            //如果channel之前没监听写事件,就开启监听
            if (!m_channel->IsWriting())
                m_channel->OnWriting();
        }
    }
    void TcpConnection::ShutdownInLoop()
    {
        m_loop->AssertInLoopThread();
        if (!m_channel->IsWriting())
            m_socket->ShutdownWrite();
    }
    void TcpConnection::ForceCloseInLoop()
    {
        m_loop->AssertInLoopThread();
        if (m_status == k_Connected || m_status == k_Disconnecting)
            handleClose();
    }
    const char* TcpConnection::StatusToString() const
    {
        switch (m_status)
        {
            case k_Disconnected:
                return "k_Disconnected";
            case k_Connecting:
                return "k_Connecting";
            case k_Connected:
                return "k_Connected";
            case k_Disconnecting:
                return "k_Disconnecting";
            default:
                return "unknown status";
        }
    }
    void TcpConnection::StartReadInLoop()
    {
        m_loop->AssertInLoopThread();
        if (!m_reading || !m_channel->IsReading())
        {
            m_channel->OnReading();
            m_reading = true;
        }
    }
    void TcpConnection::StopReadInLoop()
    {
        m_loop->AssertInLoopThread();
        if (m_reading || m_channel->IsReading())
        {
            m_channel->OffReading();
            m_reading = false;
        }
    }









    class TcpServer : uncopyable {
    public:
        using ThreadInitCallback = std::function<void(EventLoop*)>;
        enum Option {
            kNoReusePort,
            kReusePort,
        };

        TcpServer(EventLoop* loop, const SockAddr& listenAddr, const std::string& name, Option option = kNoReusePort);
        ~TcpServer();

        const std::string& ipPort() const { return m_ipPort; }
        const std::string& name() const { return m_name; }
        EventLoop* getLoop() const { return m_loop; }
        //必须在start之前调用
        void setThreadNum(int numThreads) { m_threadPool->SetThreadNum(numThreads); }
        //必须在start之前调用
        void setThreadInitCallback(const ThreadInitCallback& callback) { m_threadInitCallback = callback; }
        // 必须在start之后调用
        std::shared_ptr<EventLoopThreadPool> threadPool() { return m_threadPool; }

        //启动,线程安全
        void start();
        //连接到来或连接关闭时回调的函数,线程不安全
        void setConnectionCallback(const std::function<void(const std::shared_ptr<TcpConnection>&)>& callback)
        {
            m_connCallback = callback;
        }
        //消息到来时回调的函数,线程不安全
        void setMessageCallback(const std::function<void(const std::shared_ptr<TcpConnection>&, Buffer*, Timestamp)>& callback)
        {
            m_msgCallback = callback;
        }
        //write完成时会回调的函数,线程不安全
        void setWriteCompleteCallback(const std::function<void(const std::shared_ptr<TcpConnection>&)>& callback)
        {
            m_writeDoneCallback = callback;
        }

    private:
        using ConnectionMap = std::map<std::string, std::shared_ptr<TcpConnection>>;
        //连接到来时会回调的函数
        void newConnection(int sockfd, const SockAddr& peerAddr);
        //将这个TcpConnection从map中删除,线程安全
        void removeConnection(const std::shared_ptr<TcpConnection>& conn);
        //将这个TcpConnection从map中删除
        void removeConnectionInLoop(const std::shared_ptr<TcpConnection>& conn);

    private:
        std::atomic_bool m_started = false;
        int m_nextConnID;
        std::unique_ptr<Acceptor> m_acceptor;
        EventLoop* m_loop;  // TcpServer所属的EventLoop
        std::shared_ptr<EventLoopThreadPool> m_threadPool;
        const std::string m_ipPort;
        const std::string m_name;
        std::function<void(const std::shared_ptr<TcpConnection>&)> m_connCallback;                     //连接到来执行的回调函数
        std::function<void(const std::shared_ptr<TcpConnection>&, Buffer*, Timestamp)> m_msgCallback;  //消息到来执行的回调函数
        std::function<void(const std::shared_ptr<TcpConnection>&)> m_writeDoneCallback;                //写操作完成时执行的回调函数
        std::function<void(EventLoop*)> m_threadInitCallback;
        ConnectionMap m_connections;
    };

    TcpServer::TcpServer(EventLoop* loop, const SockAddr& listenAddr, const std::string& name, Option option)
        : m_nextConnID(1),
          m_acceptor(std::make_unique<Acceptor>(loop, listenAddr, option == kReusePort)),
          m_loop(loop),
          m_threadPool(std::make_shared<EventLoopThreadPool>(loop, name)),
          m_ipPort(listenAddr.ipPortString()),
          m_name(name)
    {
        using namespace std::placeholders;
        m_acceptor->SetConnectionCallback(std::bind(&TcpServer::newConnection, this, _1, _2));
    }
    void TcpServer::start()
    {
        if (!m_started)
        {
            m_started = true;
            m_threadPool->start(m_threadInitCallback);
            m_loop->run(std::bind(&Acceptor::listen, m_acceptor.get()));
        }
    }
    TcpServer::~TcpServer()
    {
        m_loop->AssertInLoopThread();
        LOG_TRACE << "TcpServer::~TcpServer [" << m_name << "] destructing";

        for (auto&& item : m_connections)
        {
            std::shared_ptr<TcpConnection> conn(item.second);
            item.second.reset();
            conn->GetLoop()->run(std::bind(&TcpConnection::ConnectDestroyed, conn));
        }
    }
    void TcpServer::newConnection(int sockfd, const SockAddr& peerAddr)
    {
        m_loop->AssertInLoopThread();
        EventLoop* ioLoop = m_threadPool->GetNextLoop();  //取出一个EventLoop
        char buf[64] = {0};
        fmt::format_to(buf, "-{}#{}", m_ipPort.c_str(), m_nextConnID++);
        std::string connName = m_name + buf;

        // LOG_INFO << "TcpServer::newConnection [" << m_name << "] - new connection [" << connName << "] from "
        //          << peerAddr.ipPortString();

        //创建新的TcpConnection
        SockAddr localAddr(detail::GetLocalAddr(sockfd));
        auto& conn = m_connections[connName] = std::make_shared<TcpConnection>(ioLoop, connName, sockfd, localAddr, peerAddr);

        //TcpServer将所有回调函数都传给新的TcpConnection
        conn->setConnectionCallback(m_connCallback);
        conn->setMessageCallback(m_msgCallback);
        conn->setWriteCompleteCallback(m_writeDoneCallback);
        //关闭回调函数,作用是将这个关闭的TcpConnection从map中删除
        conn->setCloseCallback(std::bind(&TcpServer::removeConnection, this, std::placeholders::_1));
        ioLoop->run(std::bind(&TcpConnection::ConnectEstablished, std::ref(conn)));
    }
    void TcpServer::removeConnection(const std::shared_ptr<TcpConnection>& conn)
    {
        // FIXME 不安全
        //因为调用TcpServer::removeConnection的线程是TcpConnection所在的EventLoop
        //也就是说TcpServer的this指针暴露在TcpConnection所在的EventLoop了
        //如果这个EventLoop对这个this指针做修改,就可能会导致TcpServer出错
        //所以理论上是不安全的,但其实并没有修改,而是立刻进入到TcpServer的EventLoop,所以其实是安全的
        //硬要说不安全,只有下面这一句话理论上不安全(其实也安全),其他全都是安全的
        m_loop->run(std::bind(&TcpServer::removeConnectionInLoop, this, conn));
    }
    void TcpServer::removeConnectionInLoop(const std::shared_ptr<TcpConnection>& conn)
    {
        m_loop->AssertInLoopThread();

        LOG_INFO << "TcpServer::removeConnectionInLoop [" << m_name << "] - connection " << conn->name();
        m_connections.erase(conn->name());

        //不直接用m_loop->run是因为TcpConnection::ConnectDestroyed应该交给其对应的EventLoop执行
        conn->GetLoop()->AddExtraFunc(std::bind(&TcpConnection::ConnectDestroyed, conn));
        //此时conn引用计数为2
        //1.conn本身   2.上面bind了一个
        //所以离开这个函数后就只剩1,然后执行完TcpConnection::ConnectDestroyed,对应的TcpConnection才真正析构
    }






}  // namespace kurisu
