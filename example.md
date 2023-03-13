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

# 3.Echo Server with `LengthFieldCodec`   
It's used much like [netty](https://github.com/netty/netty)'s `LengthFieldBasedFrameDecoder`   
This ensures that every callback has a complete msg in the buffer
```cpp  
#include <kurisu/kurisu.h>

// very similar to  netty's LengthFieldBasedFrameDecoder(65535, 0, 4, 0, 4)
kurisu::LengthFieldCodec codec = kurisu::LengthFieldCodec(65535, 0, 4, 0, 4);

void OnMsg(const std::shared_ptr<kurisu::TcpConnection>& conn, kurisu::Buffer* buf, kurisu::Timestamp)
{
    LOG_INFO << "recv msg:" << buf->ToString();
    // send through the codec, it will prepend the length to the front of the buffer
    codec.SendBufferAndDiscard(conn, buf);

    // or you can prepend the length manually like this
    // buf->PrependInt32(buf->ReadableBytes());
    // conn->Send(buf);
}

int main()
{
    kurisu::EventLoop loop;
    kurisu::TcpServer server(&loop, kurisu::SockAddr(5005), "echo");

    server.SetMessageCallback(OnMsg);


    // must be called after SetMessageCallback
    server.SetLengthFieldCodec(codec);


    server.Start();
    loop.Loop();
}
```

# 4.`Multi-thread` Chat Server with  `LengthFieldCodec`
```cpp
#include <kurisu/kurisu.h>
#include <set>

class ChatServer {
public:
    ChatServer(kurisu::EventLoop* loop, const kurisu::SockAddr& listenAddr, const std::string& name, kurisu::TcpServer::Option option = kurisu::TcpServer::k_NoReusePort)
        : m_server(loop, listenAddr, name, option),
          m_codec(65535, 0, 4, 0, 4)
    {
        using namespace std::placeholders;

        m_server.SetThreadNum(4);

        m_server.SetConnectionCallback(std::bind(&ChatServer::OnConn, this, _1));
        m_server.SetMessageCallback(std::bind(&ChatServer::OnMsg, this, _1, _2, _3));

        m_server.SetLengthFieldCodec(m_codec);
    }

    void Start() { m_server.Start(); }

private:
    void OnConn(const std::shared_ptr<kurisu::TcpConnection>& conn)
    {
        std::lock_guard locker(m_connectionsMutex);  // std::set not thread safe
        if (conn->Connected())
            m_connections.insert(conn);  // add to set
        else
            m_connections.erase(conn);  // remove from set
    }

    void OnMsg(const std::shared_ptr<kurisu::TcpConnection>& conn, kurisu::Buffer* buf, kurisu::Timestamp)
    {
        LOG_INFO << "recv msg:" << buf->ToString();

        std::lock_guard locker(m_connectionsMutex);  // std::set not thread safe
        for (auto&& it : m_connections)              // iterating the entire set
            if (it != conn)                          // if not itself
                m_codec.SendBuffer(it, buf);

        buf->DiscardAll();
    }

private:
    kurisu::TcpServer m_server;
    std::set<std::shared_ptr<kurisu::TcpConnection>> m_connections;
    std::mutex m_connectionsMutex;
    kurisu::LengthFieldCodec m_codec;
};


int main()
{
    kurisu::EventLoop loop;
    ChatServer server(&loop, kurisu::SockAddr(5005), "chat");
    server.Start();
    loop.Loop();
}
```
