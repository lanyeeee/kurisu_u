# kurisu

## Requires:  

  GCC >= 7.1(supports C++17 or above)  
  [fmt](https://github.com/fmtlib/fmt)(format the log)  
&nbsp;
## Before using it you should:  
### 1. Make sure the version of g++  and gcc >= 7.1
```
Check the g++/gcc version:
$ g++ --version
$ gcc --version
```
### 2. Install required packages
```
Ubuntu:  
$ sudo apt install cmake make
CentOS:  
$ sudo yum install cmake make
```    
&nbsp;
## Build
### build with `cmake`
make sure you are in thr root directory `kurisu_u`
```
$ mkdir build && cd build
$ cmake ..
$ make -j$(nproc)
$ sudo make install
```
&nbsp;
## Example
1.The simplest echo server
### `example.cpp`
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

2.Multi-thread echo server
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

3.Echo server with `LengthDecoder`   
very similar to  [netty](https://github.com/netty/netty)'s `LengthFieldBasedFrameDecoder`   
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
    server.SetLengthDecoder(65535, 0, 4, 0, 0);

    server.Start();
    loop.Loop();
}
```
4.Chat server with `LengthDecoder`
```cpp
#include <kurisu/kurisu.h>
#include <set>

class ChatServer {
public:
    ChatServer(kurisu::EventLoop* loop, const kurisu::SockAddr& listenAddr, const std::string& name, kurisu::TcpServer::Option option = kurisu::TcpServer::k_NoReusePort)
        : m_server(loop, listenAddr, name, option)
    {
        using namespace std::placeholders;
        m_server.SetLengthDecoder(65535, 0, 4, 0, 0);
        m_server.SetConnectionCallback(std::bind(&ChatServer::OnConn, this, _1));
        m_server.SetMessageCallback(std::bind(&ChatServer::OnMsg, this, _1, _2, _3));
    }

    void Start() { m_server.Start(); }

private:
    void OnConn(const std::shared_ptr<kurisu::TcpConnection>& conn)
    {
        if (conn->Connected())
            m_connections.insert(conn);  //add to set
        else
            m_connections.erase(conn);  //remove from set
    }

    void OnMsg(const std::shared_ptr<kurisu::TcpConnection>& conn, kurisu::Buffer* buf, kurisu::Timestamp)
    {
        LOG_INFO << "recv msg:" << buf->ToString();
        for (auto&& it : m_connections)  //iterating the entire set
            if (it != conn)              //if not itself
                it->Send(buf);
    }

private:
    kurisu::TcpServer m_server;
    std::set<std::shared_ptr<kurisu::TcpConnection>> m_connections;
};


int main()
{
    kurisu::EventLoop loop;
    ChatServer server(&loop, kurisu::SockAddr(5005), "chat");
    server.Start();
    loop.Loop();
}
```

