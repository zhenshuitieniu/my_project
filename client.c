#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h> // TCP_NODELAY
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <algorithm>
#include <pthread.h>
#include <utility>
#include <future>
#include <chrono>

#include "string_lib.h"

#define TCP_SERVER_IP           "127.0.0.1"
#define TCP_SERVER_PORT         9000
#define BUFFER_SIZE             1024
#define MAX_LOOP                (10 * 1000 * 1000)

pthread_barrier_t barrier;

typedef struct {
    int cpu_id;
    int worker_id;
    pthread_t thr;
    int local_count;
} worker_attribute;

typedef std::vector<worker_attribute>      worker_attr_vector;
worker_attr_vector g_worker_attr_vector;

static int connect_server()
{
    int fd = socket(AF_INET, SOCK_STREAM, 0 );
    if (-1 == fd) {
        PRINT_ERROR("socket() fail\n");
        return -1;
    }

    int enable = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void *)&enable, sizeof(enable)) < 0)
    {
        PRINT_ERROR("ERROR: TCP_NODELAY SETTING ERROR\n");
        close(fd);
        return -1;
    }

    struct sockaddr_in remote_addr;
    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr.s_addr = inet_addr(TCP_SERVER_IP);
    remote_addr.sin_port = htons(TCP_SERVER_PORT);
    int con_result = connect(fd, (struct sockaddr*) &remote_addr, sizeof(struct sockaddr));
    if(con_result < 0){
        PRINT_ERROR("connect Error\n");
        return -1;
    }

    struct timeval time;
    time.tv_sec = 3;
    time.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &time,sizeof(time));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &time,sizeof(time));

    return fd;
}

void* event_loop (void* arg)
{
    worker_attribute *worker_attr = (worker_attribute *) arg;
    worker_attr->local_count = 0;

    PRINT_INFO("worker: %d start\n", worker_attr->worker_id);

    int fd = connect_server();
    if ( fd < 0) {
        PRINT_ERROR("connect_server failed\n");
        return NULL;
    }

    pthread_barrier_wait(&barrier);
    PRINT_INFO("fd: %d\n", fd);

    char read_buf[BUFFER_SIZE] = { 0 };
    char write_buf[BUFFER_SIZE] = { 0 };
    for (uint64_t idx = 0; idx < MAX_LOOP; idx++) {

        std::string value = string_lib::uint64_to_str(syscall(SYS_gettid)) + "-" + string_lib::uint64_to_str(idx);
        strcpy(write_buf, value.c_str());

        int nr_write = write(fd, (void *)&write_buf, sizeof(write_buf));
        if (nr_write != sizeof(write_buf))
            PRINT_ERROR("write faile idx: %d, nr_write: %d, buff_size: %d\n", idx, nr_write, sizeof(write_buf));

        int nr_read_total = 0;
        while (nr_read_total != sizeof(read_buf)) {
            int nr_read = read(fd, read_buf + nr_read_total, sizeof(read_buf) - nr_read_total);
            if (nr_read > 0)
                nr_read_total += nr_read;
            else
                PRINT_INFO("recv data idx: %llu nr_write: %d nr_read: %d errno: %d, errstr: %s\n",
                    idx, nr_write, nr_read, errno, strerror(errno));

            if (errno == ECONNRESET)
                break;
        }

        if (! (idx % 1000000))
            PRINT_DEBUG("recheck idx: %d\n", idx);

        if (memcmp((const void *)&read_buf, (const void *)&write_buf, BUFFER_SIZE)) {
            PRINT_INFO("data err, idx: %llu, nr_write: %d nr_read: %d\n", idx, nr_write, nr_read_total);
            break;
        }
        worker_attr->local_count++;
    }

    close(fd);
    PRINT_INFO("exit\n");
    return NULL;
}

static bool test_finish_flag = false;
bool print (int flag)
{
    PRINT_INFO("start\n");

    while (!test_finish_flag) {

        uint64_t start = 0;
        for (int i = 0; i < g_worker_attr_vector.size(); i++) {
            start += g_worker_attr_vector[i].local_count;
        }

        std::this_thread::sleep_for(std::chrono::seconds(5));

        uint64_t end = 0;
        for (int i = 0; i < g_worker_attr_vector.size(); i++) {
            end += g_worker_attr_vector[i].local_count;
        }

        PRINT_INFO("iops: %d\n", (end - start) / 5 );
    }

    PRINT_INFO("finish\n");

    return 0;
}

int main()
{
    const int nr_cpu_online = sysconf(_SC_NPROCESSORS_ONLN);
    const int nr_workers = nr_cpu_online * 2;

    pthread_barrier_init(&barrier,NULL, nr_workers + 1); // nr_cpu_online + 1个等待

    for (int idx = 0; idx < nr_workers; idx++) {
        worker_attribute worker_attr;
        pthread_attr_t attr;
        cpu_set_t  cpu_info;
        pthread_attr_init(&attr);
        CPU_ZERO(&cpu_info);

        worker_attr.worker_id = idx;
        worker_attr.cpu_id = idx % nr_cpu_online;
        CPU_SET(worker_attr.cpu_id, &cpu_info);
        g_worker_attr_vector.push_back(worker_attr);

        if (0 != pthread_attr_setaffinity_np((&attr), sizeof(cpu_set_t), &cpu_info)) {
            PRINT_ERROR("set affinity failed\n");
        }

        pthread_create(&g_worker_attr_vector[idx].thr, NULL, event_loop, &g_worker_attr_vector[idx]);
    }

    pthread_barrier_wait(&barrier);

    std::future<bool> fut = std::async(std::launch::async, print, 0);

    for (int i = 0; i < g_worker_attr_vector.size(); i++) {
        pthread_join(g_worker_attr_vector[i].thr, NULL);
    }

    test_finish_flag = true;
    fut.get(); // waits for print return

    pthread_barrier_destroy(&barrier);

    return 0;
}
