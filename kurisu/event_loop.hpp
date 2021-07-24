#pragma once
#include <algorithm>
#include <mutex>
#include <vector>
#include <atomic>
#include <functional>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <map>
#include <signal.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>  // readv
#include <unistd.h>
#include <fmt/format.h>

#include "detail/socket.hpp"
#include "detail/this_thrd.hpp"
#include "time_stamp.hpp"


namespace kurisu {
    class Channel;
    class Poller;

    class EventLoop : uncopyable {
    public:
        EventLoop();
        ~EventLoop();  // force out-line dtor, for std::unique_ptr members.
        void loop();
        //可以跨线程调用，如果在其他线程调用，会调用wakeup保证退出
        void quit();
        Timestamp GetReturnTime() const { return m_returnTime; }
        int64_t GetLoopNum() const { return m_loopNum; }
        //在EventLoop所属的线程中执行此函数
        void RunInLoop(std::function<void()> cb);
        //注册只执行一次的额外任务
        void AddExtraFunc(std::function<void()> cb);


        // TimerId runAt(Timestamp time, std::function<void()> cb);

        // TimerId runAfter(double delay, std::function<void()> cb);

        // TimerId runEvery(double interval, std::function<void()> cb);

        uint64_t GetExtraFuncsNum() const;
        //唤醒阻塞在poll的loop
        void wakeup();
        //注册channel到poller的map中
        void UpdateChannel(Channel* channel);
        //从poller的map中移除channel
        void RemoveChannel(Channel* channel);
        //m_poller中是否有channel
        bool HasChannel(Channel* channel);
        pid_t GetThreadID() const { return m_threadID; }
        void AssertInLoopThread();
        bool InLoopThread() const { return m_threadID == this_thrd::tid(); }

        bool HandlingEvent() const { return m_handlingEvent; }
        //获取此线程的EventLoop
        static EventLoop* GetLoopOfThisThread();

    private:
        void WakeUpRead();
        void HandleExtraFunc();

        //DEBUG用的,打印每个事件
        void PrintActiveChannels() const;

        using ChannelList = std::vector<Channel*>;

        bool m_looping = false;           //线程是否调用了loop()
        bool m_handlingEvent = false;     //线程是否正在执行回调函数
        bool m_doingExtraFunc = false;    //  EventLoop线程是否正在执行的额外任务
        std::atomic_bool m_quit = false;  //线程是否调用了quit()
        int m_wakeUpfd;                   //一个eventfd   用于唤醒阻塞在poll的loop
        const pid_t m_threadID;
        Channel* m_thisActiveChannel = NULL;  //当前正在执行哪个channel的回调函数
        int64_t m_loopNum = 0;                //loop总循环次数
        Timestamp m_returnTime;               //有事件到来时返回的时间戳
        std::unique_ptr<Poller> m_poller;
        //std::unique_ptr<TimerQueue> timerQueue_;    //定时器
        std::unique_ptr<Channel> m_wakeUpChannel;  //用于唤醒后的回调函数
        ChannelList m_activeChannels;              // 保存所有有事件到来的channel

        //EventLoop线程每次轮询除了执行有事件到来的channel的回调函数外，也会执行这个vector内的函数（额外的任务）
        std::vector<std::function<void()>> m_ExtraFuncs;
        mutable std::mutex m_mu;  //保护m_ExtraFuncs;
    };

    namespace detail {
        //当前线程EventLoop对象指针
        inline __thread EventLoop* t_loopOfThisThread = nullptr;

        inline const int k_PollTimeoutMs = 10000;

        inline int createEventfd()
        {
            if (int evtfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC); evtfd < 0)
            {
                LOG_SYSERR << "Failed in eventfd";
                abort();
            }
            else
                return evtfd;
        }

        inline bool ignoreSigPipe = [] { return signal(SIGPIPE, SIG_IGN); }();

    }  // namespace detail

    class Channel : uncopyable {
    public:
        Channel(EventLoop* loop, int fd) : m_fd(fd), m_loop(loop) {}
        //处理事件
        void HandleEvent(Timestamp receiveTime);
        //设置可读事件回调函数
        void SetReadCallback(std::function<void(Timestamp)> cb) { m_readCallback = std::move(cb); }
        //设置可写事件回调函数
        void SetWriteCallback(std::function<void()> cb) { m_writeCallback = std::move(cb); }
        //设置关闭事件回调函数
        void SetCloseCallback(std::function<void()> cb) { m_closeCallback = std::move(cb); }
        //设置错误事件回调函数
        void SetErrorCallback(std::function<void()> cb) { m_errorCallback = std::move(cb); }

        //用于延长某些对象的生命期,使其寿命长过handleEvent()函数
        void tie(const std::shared_ptr<void>&);
        int fd() const { return m_fd; }
        //返回注册的事件
        int GetEvents() const { return m_events; }
        //设置就绪的事件
        void SetRevents(int revt) { m_revents = revt; }

        //是否未注册事件
        bool IsNoneEvent() const { return m_events == k_NoneEvent; }

        //注册可读事件
        void OnReading();
        //注销读事件
        void OffReading();
        //注册写事件
        void OnWriting();
        //注销写事件
        void OffWriting();
        //注销所有事件
        void OffAll();
        //是否已注册可读事件
        bool IsReading() const { return m_events & k_ReadEvent; }
        //是否已注册写事件
        bool IsWriting() const { return m_events & k_WriteEvent; }

        // for Poller
        int GetStatus() { return m_status; }
        void set_status(int status) { m_status = status; }

        //DEBUG 用的
        std::string ReventsString() const { return EventsToString(m_fd, m_revents); }
        std::string EventsString() const { return EventsToString(m_fd, m_events); }

        void OnLogHup() { m_logHup = true; }
        void OffLogHup() { m_logHup = false; }
        //返回所属的EventLoop
        EventLoop* GetLoop() { return m_loop; }
        //暂时离开所属的EventLoop
        void remove();

    private:
        static std::string EventsToString(int fd, int ev);

        //加入所属的EventLoop
        void update();
        //处理到来的事件
        void HandleEventWithGuard(Timestamp receiveTime);

        static const int k_NoneEvent = 0;                   //无事件
        static const int k_ReadEvent = EPOLLIN | EPOLLPRI;  //可读
        static const int k_WriteEvent = EPOLLOUT;           //可写

        bool m_tied = false;           //  是否将生命周期绑定到了外部s
        bool m_handlingEvent = false;  //是否处于处理事件中
        bool m_inLoop = false;         //是否已在EventLoop里注册
        bool m_logHup = true;          //EPOLLHUP时是否生成日志

        const int m_fd;     //此channel负责管理的文件描述符
        int m_events = 0;   //注册的事件
        int m_revents = 0;  //被poller设置的就绪的事件
        int m_status = -1;  //在poller中的状态
        EventLoop* m_loop;  //指向此channel所属的EventLoop

        std::weak_ptr<void> m_tie;                      //用来延长生命周期
        std::function<void(Timestamp)> m_readCallback;  //读事件回调函数
        std::function<void()> m_writeCallback;          //写事件回调函数
        std::function<void()> m_closeCallback;          //关闭事件回调函数
        std::function<void()> m_errorCallback;          //错误事件回调函数
    };

    class Poller : uncopyable {
    public:
        using ChannelList = std::vector<Channel*>;
        Poller(EventLoop* loop) : m_epollfd(epoll_create1(EPOLL_CLOEXEC)), m_loop(loop), m_events(k_InitEventListSize) {}
        ~Poller() = default;
        //对epoll_wait的封装
        Timestamp poll(int timeoutMs, ChannelList* activeChannels);
        //添加channel
        void UpdateChannel(Channel* channel);
        //移除channel
        void RemoveChannel(Channel* channel);
        //这个channel是否在map中
        bool HasChannel(Channel* channel) const;

        void AssertInLoopThread() const { m_loop->AssertInLoopThread(); }



    private:
        static const int k_New = -1;
        static const int k_Added = 1;
        static const int k_Deleted = 2;
        static const int k_InitEventListSize = 16;  //epoll事件表的大小

        static const char* OperationString(int op);
        //将epoll返回的到来事件加到activeChannels里
        void CollectActiveChannels(int numEvents, ChannelList* activeChannels) const;
        //注册事件,由operation决定
        void update(int operation, Channel* channel);

        using EventList = std::vector<epoll_event>;
        using ChannelMap = std::map<int, Channel*>;

        int m_epollfd;
        EventLoop* m_loop;      //指向所属的EventLoop
        EventList m_events;     //epoll事件数组
        ChannelMap m_channels;  //存储channel的map
    };







    EventLoop::EventLoop()
        :  //timerQueue_(new TimerQueue(this)),
          m_wakeUpfd(detail::createEventfd()),
          m_threadID(this_thrd::tid()),
          m_thisActiveChannel(NULL),
          m_poller(new Poller(this)),
          m_wakeUpChannel(new Channel(this, m_wakeUpfd))
    {
        LOG_DEBUG << "EventLoop created " << this << " in thread " << m_threadID;
        if (detail::t_loopOfThisThread)
            LOG_FATAL << "Another EventLoop " << detail::t_loopOfThisThread << " exists in this thread " << m_threadID;
        else
            detail::t_loopOfThisThread = this;
        m_wakeUpChannel->SetReadCallback(std::bind(&EventLoop::WakeUpRead, this));  //以便调用quit时唤醒loop
        m_wakeUpChannel->OnReading();
    }
    inline EventLoop::~EventLoop()
    {
        LOG_DEBUG << "EventLoop " << this << " of thread " << m_threadID
                  << " destructs in thread " << this_thrd::tid();
        m_wakeUpChannel->OffAll();
        m_wakeUpChannel->remove();
        close(m_wakeUpfd);
        detail::t_loopOfThisThread = NULL;
    }
    inline void EventLoop::loop()
    {
        AssertInLoopThread();
        m_looping = true;
        m_quit = false;
        LOG_TRACE << "EventLoop " << this << " start looping";

        while (!m_quit)
        {
            m_activeChannels.clear();  //删除所有active channel

            //没事的时候loop会阻塞在这里
            m_returnTime = m_poller->poll(detail::k_PollTimeoutMs, &m_activeChannels);
            ++m_loopNum;
            if (Logger::level() <= Logger::LogLevel::TRACE)
                PrintActiveChannels();  //将发生的事件写入日志

            m_handlingEvent = true;
            //执行每个有事件到来的channel的回调函数
            for (auto&& channel : m_activeChannels)
            {
                m_thisActiveChannel = channel;
                m_thisActiveChannel->HandleEvent(m_returnTime);  //TODO  为什么不一步到位
            }
            m_thisActiveChannel = NULL;
            m_handlingEvent = false;
            HandleExtraFunc();  //执行额外的回调函数
        }

        LOG_TRACE << "EventLoop " << this << " stop looping";
        m_looping = false;
    }
    inline void EventLoop::quit()
    {
        m_quit = true;
        if (!InLoopThread())
            wakeup();
    }
    inline void EventLoop::RunInLoop(std::function<void()> cb)
    {
        if (InLoopThread())
            cb();
        else
            AddExtraFunc(std::move(cb));
    }
    inline void EventLoop::AddExtraFunc(std::function<void()> cb)
    {
        {
            std::lock_guard lock(m_mu);
            m_ExtraFuncs.emplace_back(std::move(cb));
        }

        if (!InLoopThread() || m_doingExtraFunc)
            wakeup();
    }
    inline uint64_t EventLoop::GetExtraFuncsNum() const
    {
        std::lock_guard lock(m_mu);
        return m_ExtraFuncs.size();
    }
    inline void EventLoop::wakeup()
    {
        uint64_t one = 1;
        ssize_t n = detail::Write(m_wakeUpfd, &one, sizeof(one));
        if (n != sizeof(one))
            LOG_ERROR << "EventLoop::wakeup() writes " << n << " bytes instead of 8";
    }
    inline void EventLoop::UpdateChannel(Channel* channel)
    {
        AssertInLoopThread();
        m_poller->UpdateChannel(channel);
    }
    inline void EventLoop::RemoveChannel(Channel* channel)
    {
        AssertInLoopThread();
        m_poller->RemoveChannel(channel);
    }
    inline bool EventLoop::HasChannel(Channel* channel)
    {
        AssertInLoopThread();
        return m_poller->HasChannel(channel);
    }
    inline EventLoop* EventLoop::GetLoopOfThisThread() { return detail::t_loopOfThisThread; }
    inline void EventLoop::WakeUpRead()
    {
        uint64_t one = 1;
        ssize_t n = detail::Read(m_wakeUpfd, &one, sizeof one);
        if (n != sizeof(one))
            LOG_ERROR << "EventLoop::WakeUpRead() reads " << n << " bytes instead of 8";
    }
    inline void EventLoop::HandleExtraFunc()
    {
        std::vector<std::function<void()>> functors;
        m_doingExtraFunc = true;

        {
            std::lock_guard lock(m_mu);
            functors.swap(m_ExtraFuncs);
        }
        //既减少了持有锁的时间，也防止了死锁(func里可能也调用了HandleExtraFunc()

        for (auto&& func : functors)
            func();

        m_doingExtraFunc = false;
    }
    inline void EventLoop::PrintActiveChannels() const
    {
        for (auto&& channel : m_activeChannels)
            LOG_TRACE << "{" << channel->ReventsString() << "} ";
    }
    inline void EventLoop::AssertInLoopThread()
    {
        if (!InLoopThread())
            LOG_FATAL << "EventLoop::abortNotInLoopThread - EventLoop " << this
                      << " was created in threadId_ = " << m_threadID
                      << ", current thread id = " << this_thrd::tid();
    }




    inline void Channel::HandleEvent(Timestamp receiveTime)
    {
        std::shared_ptr<void> guard;
        if (m_tied)
        {
            guard = m_tie.lock();
            if (guard)  //如果绑定的对象还活着
                HandleEventWithGuard(receiveTime);
        }
        else
            HandleEventWithGuard(receiveTime);
    }
    inline void Channel::tie(const std::shared_ptr<void>& obj)
    {
        m_tie = obj;
        m_tied = true;
    }
    inline void Channel::remove()
    {
        m_inLoop = false;
        m_loop->RemoveChannel(this);
    }
    inline std::string Channel::EventsToString(int fd, int ev)
    {
        std::string str = fmt::format("{}: ", fd);
        str.reserve(32);
        if (ev & EPOLLIN)
            str += "IN ";
        if (ev & EPOLLPRI)
            str += "PRI ";
        if (ev & EPOLLOUT)
            str += "OUT ";
        if (ev & EPOLLHUP)
            str += "HUP ";
        if (ev & EPOLLRDHUP)
            str += "RDHUP ";
        if (ev & EPOLLERR)
            str += "ERR ";

        return str;
    }
    inline void Channel::update()
    {
        m_inLoop = true;
        m_loop->UpdateChannel(this);
    }
    inline void Channel::HandleEventWithGuard(Timestamp receiveTime)
    {
        m_handlingEvent = true;
        LOG_TRACE << ReventsString();
        if ((m_revents & EPOLLHUP) && !(m_revents & EPOLLIN))
        {
            if (m_logHup)
                LOG_WARN << "fd = " << m_fd << " Channel::HandleEvent() EPOLLHUP";
            if (m_closeCallback)
                m_closeCallback();
        }

        if (m_revents & EPOLLERR)
        {
            if (m_errorCallback)
                m_errorCallback();
        }
        if (m_revents & (EPOLLIN | EPOLLPRI | EPOLLRDHUP))
        {
            if (m_readCallback)
                m_readCallback(receiveTime);
        }
        if (m_revents & EPOLLOUT)
        {
            if (m_writeCallback)
                m_writeCallback();
        }
        m_handlingEvent = false;
    }
    inline void Channel::OnReading()
    {
        m_events |= k_ReadEvent;
        update();
    }
    inline void Channel::OffReading()
    {
        m_events &= ~k_ReadEvent;
        update();
    }
    inline void Channel::OnWriting()
    {
        m_events |= k_WriteEvent;
        update();
    }
    inline void Channel::OffWriting()
    {
        m_events &= ~k_WriteEvent;
        update();
    }
    inline void Channel::OffAll()
    {
        m_events = k_NoneEvent;
        update();
    }



    inline Timestamp Poller::poll(int timeoutMs, ChannelList* activeChannels)
    {
        LOG_TRACE << "fd total count " << m_channels.size();
        int numEvents = epoll_wait(m_epollfd, &*m_events.begin(), (int)m_events.size(), timeoutMs);
        int tmpErrno = errno;
        Timestamp now;
        if (numEvents > 0)
        {
            LOG_TRACE << numEvents << " events happened";
            CollectActiveChannels(numEvents, activeChannels);
            if ((uint64_t)numEvents == m_events.size())
                m_events.resize(m_events.size() * 2);  //说明m_events的大小要不够用了，扩容
        }
        else if (numEvents == 0)
        {
            LOG_TRACE << "nothing happened";
        }
        else if (tmpErrno != EINTR)
        {
            errno = tmpErrno;
            LOG_SYSERR << "Poller::poll()";
        }
        return now;
    }
    inline void Poller::UpdateChannel(Channel* channel)
    {
        Poller::AssertInLoopThread();
        const int status = channel->GetStatus();
        LOG_TRACE << "fd = " << channel->fd()
                  << " events = " << channel->GetEvents() << " index = " << status;
        if (status == k_New || status == k_Deleted)  //新的或之前被移出epoll但没有从ChannelMap里删除的
        {
            int fd = channel->fd();
            if (status == k_New)           //如果是新的
                m_channels[fd] = channel;  //在ChannelMap里注册

            //旧的就不用注册到ChannelMap里了
            channel->set_status(k_Added);    //设置状态为已添加
            update(EPOLL_CTL_ADD, channel);  //将channel对应的fd注册到epoll中
        }
        else  //修改
        {
            if (channel->IsNoneEvent())  //此channel是否未注册事件
            {
                update(EPOLL_CTL_DEL, channel);  //直接从epoll中删除
                channel->set_status(k_Deleted);  //只代表不在epoll中，不代表已经从ChannelMap中移除
            }
            else
                update(EPOLL_CTL_MOD, channel);  //修改(更新)事件
        }
    }
    inline bool Poller::HasChannel(Channel* channel) const
    {
        AssertInLoopThread();
        auto it = m_channels.find(channel->fd());
        return it != m_channels.end() && it->second == channel;
    }
    inline void Poller::RemoveChannel(Channel* channel)
    {
        Poller::AssertInLoopThread();
        int fd = channel->fd();
        LOG_TRACE << "fd = " << fd;
        int status = channel->GetStatus();
        m_channels.erase(fd);  //从ChannelMap中移除

        if (status == k_Added)               //如果已在epoll中注册
            update(EPOLL_CTL_DEL, channel);  //就从epoll中移除
        channel->set_status(k_New);
    }
    inline const char* Poller::OperationString(int op)
    {
        switch (op)
        {
            case EPOLL_CTL_ADD:
                return "ADD";
            case EPOLL_CTL_DEL:
                return "DEL";
            case EPOLL_CTL_MOD:
                return "MOD";
            default:
                return "Unknown Operation";
        }
    }
    inline void Poller::CollectActiveChannels(int numEvents, ChannelList* activeChannels) const
    {
        for (int i = 0; i < numEvents; ++i)
        {
            Channel* channel = (Channel*)m_events[i].data.ptr;
            channel->SetRevents(m_events[i].events);
            activeChannels->emplace_back(channel);
        }
    }
    inline void Poller::update(int operation, Channel* channel)
    {
        epoll_event event;
        memset(&event, 0, sizeof(event));
        event.events = channel->GetEvents();
        event.data.ptr = channel;  //这一步使得在epoll_wait返回时能通过data.ptr访问对应的channel
        int fd = channel->fd();
        LOG_TRACE << "epoll_ctl op = " << OperationString(operation)
                  << " fd = " << fd << " event = { " << channel->EventsString() << " }";

        if (epoll_ctl(m_epollfd, operation, fd, &event) < 0)  //将fd注册到epoll中
        {
            if (operation == EPOLL_CTL_DEL)
                LOG_SYSERR << "epoll_ctl op =" << OperationString(operation) << " fd =" << fd;
            else
                LOG_SYSFATAL << "epoll_ctl op =" << OperationString(operation) << " fd =" << fd;
        }
    }


}  // namespace kurisu