#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <algorithm>
#include <pthread.h>
#include <utility>
#include <netinet/tcp.h> // TCP_NODELAY
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "string_lib.h"

#define LISTEN_BACKLOG    128
#define TCP_SERVER_PORT   9000
#define BUFFER_SIZE       1024
#define MAX_EPOLL_SIZE    1024

#define MAX_EVENTS              1024
#define MAX_EPOOL_TIMEOUT       100

#define MAX_NUM_STREAM_LISTENERS 8
#define MAX_NUM_THREADS_PER_CORE 4

typedef struct {
    int is_host;
    int numa_id;
    int cpu_id;
    uint64_vector pair_fd;
    int pair_fd_index;
    pthread_t thr;
} worker_attribute;

typedef std::vector<worker_attribute>      worker_attr_vector;
typedef worker_attr_vector::iterator       worker_attr_vector_iter;
typedef worker_attr_vector::const_iterator worker_attr_vector_const_iter;

worker_attr_vector g_worker_attr_vector;


typedef struct
{
    /** timeout call back
    * when in an event loop it can return any non zero value to stop the eventloop
    */
    /** timeout duration */
    size_t timeout;
    /** epoll file descriptor*/
    int epoll_fd;

    /** listen socket file descriptor*/
    int tcpfd_listener;

    /** user data for poll_event */
    void * data; // worker_attribute
} epoll_ctx;

int event_dispatch(epoll_ctx *ctx);

epoll_ctx * epoll_ctx_create(int tcpfd)
{
    epoll_ctx *ectx = (epoll_ctx *)malloc(sizeof(epoll_ctx));
    if (!ectx) {
        PRINT_ERROR("calloc failed at poll_event\n");
        return NULL;
    }

    ectx->timeout = MAX_EPOOL_TIMEOUT;
    ectx->epoll_fd = epoll_create(MAX_EVENTS);
    ectx->tcpfd_listener = tcpfd;
    PRINT_INFO("Created a new epoll ctx, tcpfd_listener: %d\n", tcpfd);
    return ectx;
}

static int setnonblocking (int sfd)
{
    int flags = fcntl (sfd, F_GETFL, 0);
    if (flags == -1) {
        PRINT_ERROR("get socket fd error!\n");
        return -1;
    }

    if (fcntl (sfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        PRINT_ERROR("set socket fd to nonbloack error!\n");
        return -1;
    }
    return 0;
}

static int set_sock_opt (int fd)
{
    struct timeval time;
    time.tv_sec = 3;
    time.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &time, sizeof(time)) < 0)
        PRINT_ERROR("setsockopt()");
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &time, sizeof(time)) < 0)
        PRINT_ERROR("setsockopt()");

    int no_delay = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char*)&no_delay, sizeof(no_delay)) < 0)
        PRINT_ERROR("setsockopt()");

    int keep_alive = 1;
    if(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char*)&keep_alive, sizeof(keep_alive)) < 0)
       PRINT_ERROR("setsockopt()");

#if 0
   if (fd is PF_INET) {
      int keepIdle = 20;
      int keepInterval = 3;
      int keepCount = 3;
      if (setsockopt(connfd, SOL_TCP, TCP_KEEPIDLE, (void*)&keepIdle, sizeof(keepIdle)) != 0)
         PRINT_ERROR("setsockopt()");
      if (setsockopt(connfd, SOL_TCP, TCP_KEEPINTVL, (void*)&keepInterval, sizeof(keepInterval)) != 0)
         PRINT_ERROR("setsockopt()");
      if (setsockopt(connfd, SOL_TCP, TCP_KEEPCNT, (void*)&keepCount, sizeof(keepCount)) != 0)
         PRINT_ERROR("setsockopt()");
      int timeoutMs = 3000;
      if (setsockopt(this, IPPROTO_TCP, TCP_USER_TIMEOUT, (void*)&timeoutMs, sizeof(timeoutMs)) != 0)
         PRINT_ERROR("setsockopt()");
   }
#endif

    return 0;
}

static void  poll_event_add(epoll_ctx *ctx, int fd)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    ev.data.fd = fd;   //set connected socket fd to epoll struct
    ev.events  = EPOLLIN | EPOLLET;

    PRINT_INFO("EPOLL_CTL_ADD: %d\n", fd);
    epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev);	//add a new tcp connection to epoll
}

static void poll_event_read(epoll_ctx *ctx, int fd)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    ev.data.fd = fd;
    ev.events = EPOLLIN | EPOLLET;
    epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, fd, &ev);
}

static void poll_event_write(epoll_ctx *ctx, int fd)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    ev.data.fd = fd;
    ev.events = EPOLLOUT | EPOLLET;
    epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, fd, &ev);
}

static void poll_event_remove(epoll_ctx *ctx, int fd)
{
    PRINT_INFO("EPOLL_CTL_DEL: %d\n", fd);
    epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    close(fd);
}

static void poll_event_loop(epoll_ctx *ctx)
{
    worker_attribute *work_attr = (worker_attribute *)ctx->data;

    // notify all handlers
    int epoll_fd = ctx->epoll_fd;
    for (int index = 0; index < work_attr->pair_fd.size(); index ++) {
        PRINT_INFO("notify epoll_fd: %d pair_fd: %d\n", epoll_fd, work_attr->pair_fd[index]);
        if (write(work_attr->pair_fd[index], &epoll_fd , sizeof(epoll_fd) )	== -1 ) {
            PRINT_ERROR("Write socket error:%s\n", strerror(errno));
            exit(1);
        }
    }

    while(!event_dispatch(ctx));
}

int socket_connfd(int sock_fd)
{
    struct sockaddr_in clientaddr;
    socklen_t socklen = sizeof(clientaddr);
    int connfd = accept(sock_fd,(struct sockaddr *)&clientaddr, &socklen);
    if (connfd < 0) {
        PRINT_ERROR("connfd failed\n");
        return -1;;
    }

    char *str_ip = inet_ntoa(clientaddr.sin_addr);
    PRINT_INFO("accept a conn from %s, sock_fd: %d connfd: %d\n", str_ip, sock_fd, connfd);

    return connfd;
}

void socket_send_data(int sock_fd, char* buf)
{
    struct sockaddr_in client_addr;
    socklen_t socklen = sizeof(client_addr);
    getpeername(sock_fd, (struct sockaddr *)&client_addr, &socklen);

    PRINT_DEBUG("WRITE: %s\n", buf);

    int send_size = send(sock_fd, buf, BUFFER_SIZE, 0);
    if(send_size < 0) {
        PRINT_ERROR("send data to client:%s port:%d error, errno:%d, errstr:%s\n",
            inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), errno, strerror(errno));
    }
}

int socket_recv_data(epoll_ctx *ctx, int sock_fd, char* buf)
{
    int recv_size = recv(sock_fd, buf, BUFFER_SIZE, 0);
    if (recv_size < 0) {
        if (errno == ECONNRESET) {
            PRINT_ERROR("close tcp connection, sockfd:%d\n", sock_fd);
            poll_event_remove(ctx, sock_fd);
        } else {
            if (errno != EAGAIN) // 11 try again
                PRINT_ERROR("recv data from sockfd(%d) errno:%d, errstr:%s\n", sock_fd, errno, strerror(errno));
        }
    } else if (recv_size == 0) {
        struct sockaddr_in client_addr;
        socklen_t socklen = sizeof(client_addr);
        getpeername(sock_fd, (struct sockaddr *)&client_addr, &socklen);
        PRINT_ERROR("client:%s, close tcp connection, sockfd:%d\n", inet_ntoa(client_addr.sin_addr), sock_fd);
        poll_event_remove(ctx, sock_fd);
    } else {
        //buf[recv_size - 1] = '\0';
        PRINT_DEBUG("-----**----read data: %s\n", buf);
    }

    if (recv_size != BUFFER_SIZE && recv_size != -1)
        PRINT_ERROR("recv_size: %d\n", recv_size);

    return recv_size;
}

int event_dispatch(epoll_ctx *ctx)
{
    worker_attribute *work_attr = (worker_attribute *)ctx->data;
    const int nr_pair_fd = work_attr->pair_fd.size();
    const int epoll_fd = ctx->epoll_fd;

    struct epoll_event events[MAX_EPOLL_SIZE];
    int nfds = epoll_wait(epoll_fd, events, MAX_EPOLL_SIZE, -1); //epollfd, epoll events, max events, timeout
    PRINT_DEBUG("wait end nfds = %d\n", nfds);

    int record = 0;
    for (int i = 0; i < nfds; ++i) {

        const int sock_fd = events[i].data.fd;
        PRINT_DEBUG("read epoll_fd: %d sock_fd: %d tcpfd_listener: %d\n", epoll_fd, sock_fd, ctx->tcpfd_listener);
        if (sock_fd < 0) {
            PRINT_ERROR("invalid sockfd:%d\n", sock_fd);
            continue;
        }

        if (sock_fd == ctx->tcpfd_listener) { //if it's tcp epoll event fd, means need to create a new tcp connection

            int connfd = socket_connfd(sock_fd);
            if (connfd >= 0) {
                setnonblocking(connfd);
                set_sock_opt(connfd);
                poll_event_add(ctx, connfd);
            }

        //do process with different event type fot tcp connections
        } else if(events[i].events & EPOLLIN) {

            const int index = work_attr->pair_fd_index++ % nr_pair_fd;
            PRINT_DEBUG("EPOLLIN notify pair_fd: %d epoll_fd: %d sock_fd: %d\n", work_attr->pair_fd[index], epoll_fd, sock_fd);

            record++;

            if (! (work_attr->pair_fd_index % 1000000))
                PRINT_INFO("notify idx: %d\n", work_attr->pair_fd_index);

#if 1
            if (write(work_attr->pair_fd[index] , &sock_fd , sizeof(sock_fd) )  == -1 ) {
                PRINT_ERROR("Write socket error:%s\n", strerror(errno));
                continue;
            }
#else
            char buf[BUFFER_SIZE] = {0};
            socket_recv_data(ctx, sock_fd, buf);
            poll_event_write(ctx, sock_fd);
#endif
        } else if(events[i].events & EPOLLOUT) {

#if 0
            char buf[BUFFER_SIZE] = {0};
            socket_send_data(sock_fd, buf);
            poll_event_read(ctx, sock_fd);
#endif
        }
    }

    if (record != nfds)
        PRINT_DEBUG("nfds:%d record: %d\n", nfds, record);
    return 0;
}

void *event_dispatcher(void *ptr)
{
    struct sockaddr_in tcp_serveraddr;

    worker_attribute *ctx = (worker_attribute *)ptr;

    int tcpfd_listener = socket(AF_INET, SOCK_STREAM, 0);
    if(tcpfd_listener < 0)
        PRINT_ERROR("tfd_listener create error\n");

#if 1
    /*set SO_REUSEADDR and SO_REUSEPORT*/
    int opt = SO_REUSEADDR;
    if (setsockopt(tcpfd_listener, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        PRINT_ERROR("setsockopt()");

    opt = SO_REUSEPORT;
    if (setsockopt(tcpfd_listener, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))<0)
        PRINT_ERROR("setsockopt()");
#endif

    setnonblocking(tcpfd_listener);
    set_sock_opt(tcpfd_listener);

    bzero(&tcp_serveraddr, sizeof(tcp_serveraddr));
    tcp_serveraddr.sin_family = AF_INET;
    tcp_serveraddr.sin_addr.s_addr = INADDR_ANY;
    tcp_serveraddr.sin_port = htons(TCP_SERVER_PORT);

    PRINT_INFO("TCP PORT:%d\n", TCP_SERVER_PORT);

    //bind tcp socket server address and port
    if(bind(tcpfd_listener,(struct sockaddr *)&tcp_serveraddr, sizeof(struct sockaddr))== -1)
        PRINT_ERROR("tcpfd_listener bind error\n");

    epoll_ctx *ectx = epoll_ctx_create(tcpfd_listener);
    ectx->data = ctx;

    struct epoll_event epoll_ev;
    epoll_ev.data.fd = tcpfd_listener;
    epoll_ev.events = EPOLLIN; // can't used EPOLLET in connect
    epoll_ctl(ectx->epoll_fd, EPOLL_CTL_ADD, tcpfd_listener, &epoll_ev);

    int ret = listen(tcpfd_listener, LISTEN_BACKLOG);  //listen tcp socket fd
    if(ret < 0) {
        PRINT_ERROR("listen tcp socket fd error\n");
    }

    poll_event_loop(ectx);

    free(ectx);
}

void *event_handler(void *ptr) {

    epoll_ctx ectx;
    worker_attribute *work_ctx = (worker_attribute *)ptr;

    // first handcheck
    int epoll_fd = 0;
    if (read(work_ctx->pair_fd[0], &epoll_fd , sizeof(epoll_fd)) == -1) {
        PRINT_ERROR("Read from socket error:%s\n", strerror(errno) );
        exit(1);
    }

    ectx.epoll_fd = epoll_fd;
    PRINT_INFO("update epoll_fd: %d pair_fd: %d\n", epoll_fd, work_ctx->pair_fd[0]);

    char buf[BUFFER_SIZE] = {0};
    while (true) {
        int sock_fd = 0;
        if (read(work_ctx->pair_fd[0], &sock_fd , sizeof(sock_fd)) == -1) {
            PRINT_ERROR("Read from socket error:%s\n", strerror(errno) );
            continue;
        }

        PRINT_DEBUG("Read pair_fd: %d epoll_fd: %d, sock_fd: %d\n", work_ctx->pair_fd[0], epoll_fd, sock_fd);


        if (socket_recv_data(&ectx, sock_fd, (char* )&buf) <= 0)
            continue;

        poll_event_write(&ectx, sock_fd);

        socket_send_data(sock_fd, (char* )&buf);
        poll_event_read(&ectx, sock_fd);
    }
}

int main()
{
    int num_numa_node = get_num_numa_nodes();
    int nr_listener_per_node = MAX(1, MAX(MAX_NUM_STREAM_LISTENERS, 1) / num_numa_node);

    int numa_id = 0;
    for (numa_id = 0; numa_id < num_numa_node; numa_id++) {
        cpu_set_t out_cpu_set;
        uint64_vector out_cpu_ids;
        get_numa_cores_by_node(numa_id, &out_cpu_set, &out_cpu_ids);
        nr_listener_per_node = MIN(nr_listener_per_node, MAX(1, out_cpu_ids.size() / MAX_NUM_THREADS_PER_CORE));
        std::sort(out_cpu_ids.begin(), out_cpu_ids.end());

        uint64_vector pair_fd;

        int cpu_iter = 0;
        for (cpu_iter = 0; cpu_iter < (out_cpu_ids.size() - nr_listener_per_node); cpu_iter++) {
            for (int k = 0; k < MAX_NUM_THREADS_PER_CORE; k++) {
                int fd[2];
                if (socketpair(AF_UNIX, SOCK_STREAM, 0, (int *)&fd[0]) == -1 ) {
                    PRINT_ERROR("create unnamed socket pair failed:%s\n", strerror(errno) );
                    exit(-1);
                }
                uint64_vector ivec(1, fd[1]);
                worker_attribute attr = {false, numa_id, out_cpu_ids[cpu_iter], ivec};

                g_worker_attr_vector.push_back(attr);
                pair_fd.push_back(fd[0]);
            }
        }

        int idx = 0;
        const int nr_pair_in_one_host = pair_fd.size() / nr_listener_per_node;
        for ( ; cpu_iter < out_cpu_ids.size(); cpu_iter++) {
            uint64_vector_iter iter = pair_fd.begin() + nr_pair_in_one_host * idx;
            uint64_vector ivec;
            if (cpu_iter == out_cpu_ids.size() - 1)
                ivec.insert(ivec.begin(), iter, pair_fd.end());
            else
                ivec.insert(ivec.begin(), iter, iter + nr_pair_in_one_host);

            worker_attribute attr = {true, numa_id, out_cpu_ids[cpu_iter], ivec};

            g_worker_attr_vector.push_back(attr);
            idx++;
        }
    }

    for (int i = 0; i < g_worker_attr_vector.size(); i++) {
        PRINT_INFO("%s thread: %d numa: %d cpuid: %d pair_fd: %s\n",
            g_worker_attr_vector[i].is_host ? "host" : "target" ,
            i, g_worker_attr_vector[i].numa_id, g_worker_attr_vector[i].cpu_id,
            (string_lib::uint64_vec_to_str((const uint64_vector*)&g_worker_attr_vector[i].pair_fd)).c_str());
    }

    int nr_cpu_online = sysconf(_SC_NPROCESSORS_ONLN);
    for (int i = 0; i < g_worker_attr_vector.size(); i++) {
        pthread_attr_t attr;
        cpu_set_t  cpu_info;
        pthread_attr_init(&attr);
        CPU_ZERO(&cpu_info);
        CPU_SET(g_worker_attr_vector[i].cpu_id, &cpu_info);

        if (0 != pthread_attr_setaffinity_np((&attr), sizeof(cpu_set_t), &cpu_info)) {
            PRINT_ERROR("set affinity failed\n");
        }

        if (g_worker_attr_vector[i].is_host)
            pthread_create(&g_worker_attr_vector[i].thr, &attr, event_dispatcher, &g_worker_attr_vector[i]);
        else
            pthread_create(&g_worker_attr_vector[i].thr, &attr, event_handler, &g_worker_attr_vector[i]);
    }

    for (int i = 0; i < g_worker_attr_vector.size(); i++) {
        pthread_join(g_worker_attr_vector[i].thr, NULL);
    }
}
