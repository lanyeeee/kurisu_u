# 1.The simplest Echo Server
## `example.cpp`
```cpp
#include <kurisu/kurisu.h>

int main()
{
    kurisu::EventLoop loop;
    kurisu::TcpServer server(&loop, kurisu::SockAddr(5005), "echo"); //listen port 5005

    server.SetMessageCallback([](const std::shared_ptr<kurisu::TcpConnection>& conn, kurisu::Buffer* buf, kurisu::Timestamp) {
        LOG_INFO << "recv msg:" << buf->ToString();
        conn->Send(buf);
    });

    server.Start();
    loop.Loop();
}
```
### compile
```
$ g++ ./example.cpp -o example -std=c++17 -pthread -lkurisu
```
### run
```
./example
```
Then the echo server will listen port 5005   

# 2.`Multi-thread` Echo Server
```cpp
#include <kurisu/kurisu.h>

void OnMsg(const std::shared_ptr<kurisu::TcpConnection>& conn, kurisu::Buffer* buf, kurisu::Timestamp)
{
    LOG_INFO << "recv msg:" << buf->ToString();
    conn->Send(buf);
}

int main()
{
    kurisu::EventLoop loop;
    kurisu::TcpServer server(&loop, kurisu::SockAddr(5005), "echo"); //listen port 5005

    server.SetMessageCallback(OnMsg);

    //TODO  this is the same as above
    // server.SetMessageCallback([](const std::shared_ptr<kurisu::TcpConnection>& conn, kurisu::Buffer* buf, kurisu::Timestamp) {
    //     LOG_INFO << "recv msg:" << buf->ToString();
    //     conn->Send(buf);
    // });

    // 4 threads
    server.SetThreadNum(4); 
    server.Start();
    loop.Loop();
}
```

# 3.Echo Server with `LengthFieldDecoder`   
It's used much like [netty](https://github.com/netty/netty)'s `LengthFieldBasedFrameDecoder`   
This ensures that every callback has a complete msg in the buffer
```cpp  
#include <kurisu/kurisu.h>

void OnMsg(const std::shared_ptr<kurisu::TcpConnection>& conn, kurisu::Buffer* buf, kurisu::Timestamp)
{
    LOG_INFO << "recv msg:" << buf->ToString();
    conn->Send(buf);
}

int main()
{
    kurisu::EventLoop loop;
    kurisu::TcpServer server(&loop, kurisu::SockAddr(5005), "echo");

    server.SetMessageCallback(OnMsg);

    //very similar to  netty's LengthFieldBasedFrameDecoder
    server.SetLengthFieldDecoder(65535, 0, 4, 0, 0);

    server.Start();
    loop.Loop();
}
```
# 4.Echo Server with `LengthFieldDecoder` and `Heartbeat`   
```cpp
#include <kurisu/kurisu.h>

void OnMsg(const std::shared_ptr<kurisu::TcpConnection>& conn, kurisu::Buffer* buf, kurisu::Timestamp)
{
    LOG_INFO << "recv msg:" << buf->ToString();
    conn->Send(buf);
}

int main()
{
    kurisu::EventLoop loop;
    kurisu::TcpServer server(&loop, kurisu::SockAddr(5005), "echo");

    server.SetMessageCallback(OnMsg);

    //very similar to  netty's LengthFieldBasedFrameDecoder
    server.SetLengthFieldDecoder(65535, 0, 4, 0, 0);

    std::string msg = "heartbeat";
    //If you don't set it, the default msg is "\0\0\0\0",4 bytes total
    server.SetHeartbeatMsg(msg.data(), (int)msg.size());
    server.SetHeartbeatInterval(5);  //Send heartbeat msg every 5 seconds.

    server.Start();
    loop.Loop();
}

```  
# 5.Echo server with `LengthFieldDecoder`,`Heartbeat`,`ShutdownTimingWheel`  
If a connection in **ShundownTimingWheel** does not send any msg within the `interval` you set, it will be **forcibly closed**
```cpp
#include <kurisu/kurisu.h>

void OnMsg(const std::shared_ptr<kurisu::TcpConnection>& conn, kurisu::Buffer* buf, kurisu::Timestamp)
{
    LOG_INFO << "recv msg:" << buf->ToString();
    conn->Send(buf);
}

void OnConn(const std::shared_ptr<kurisu::TcpConnection>& conn)
{
    // If you want this connection to be added to the ShutdownTimingWheel
    // you need to call the AddToShutdownTimingWheel()

    // in this example all connections added
    if (conn->Connected())
        conn->AddToShutdownTimingWheel();
}
int main()
{
    kurisu::EventLoop loop;
    kurisu::TcpServer server(&loop, kurisu::SockAddr(5005), "echo");

    server.SetMessageCallback(OnMsg);
    server.SetConnectionCallback(OnConn);

    // very similar to  netty's LengthFieldBasedFrameDecoder
    server.SetLengthFieldDecoder(65535, 0, 4, 0, 0);

    std::string msg = "heartbeat";
    // If you don't set it, the default msg is "\0\0\0\0",4 bytes total
    server.SetHeartbeatMsg(msg.data(), (int)msg.size());
    server.SetHeartbeatInterval(5);  // Send heartbeat msg every 5 seconds.

    // If no msg comes from the client for 15 seconds, it will be forcibly closed
    server.SetShutdownInterval(15);

    server.Start();
    loop.Loop();
}
```



# 6.`Multi-thread` Chat Server with  `LengthFieldDecoder`,`Heartbeat`,`ShutdownTimingWheel`
```cpp
#include <kurisu/kurisu.h>
#include <set>

class ChatServer {
public:
    ChatServer(kurisu::EventLoop* loop, const kurisu::SockAddr& listenAddr, const std::string& name, kurisu::TcpServer::Option option = kurisu::TcpServer::k_NoReusePort)
        : m_server(loop, listenAddr, name, option)
    {
        using namespace std::placeholders;

        m_server.SetThreadNum(4);
        m_server.SetLengthFieldDecoder(65535, 0, 4, 0, 0);

        std::string msg = "heartbeat";
        m_server.SetHeartbeatMsg(msg.data(), (int)msg.size());
        m_server.SetHeartbeatInterval(5);

        // If no msg comes from the client for 2 minutes, it will be forced to close
        m_server.SetShutdownInterval(120);

        m_server.SetConnectionCallback(std::bind(&ChatServer::OnConn, this, _1));
        m_server.SetMessageCallback(std::bind(&ChatServer::OnMsg, this, _1, _2, _3));
    }

    void Start() { m_server.Start(); }

private:
    void OnConn(const std::shared_ptr<kurisu::TcpConnection>& conn)
    {
        std::lock_guard locker(m_connectionsMutex);  // std::set not thread safe
        if (conn->Connected())
        {
            conn->AddToShutdownTimingWheel();  // add to ShutdownTimingWheel
            m_connections.insert(conn);        // add to set
        }
        else
            m_connections.erase(conn);  // remove from set
    }

    void OnMsg(const std::shared_ptr<kurisu::TcpConnection>& conn, kurisu::Buffer* buf, kurisu::Timestamp)
    {
        LOG_INFO << "recv msg:" << buf->ToString();
        std::lock_guard locker(m_connectionsMutex);  // std::set not thread safe
        for (auto&& it : m_connections)              // iterating the entire set
            if (it != conn)                          // if not itself
                it->Send(buf);
    }

private:
    kurisu::TcpServer m_server;
    std::set<std::shared_ptr<kurisu::TcpConnection>> m_connections;
    std::mutex m_connectionsMutex;
};


int main()
{
    kurisu::EventLoop loop;
    ChatServer server(&loop, kurisu::SockAddr(5005), "chat");
    server.Start();
    loop.Loop();
}
```
