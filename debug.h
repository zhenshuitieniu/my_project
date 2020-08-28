#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <cxxabi.h>
#include <cassert>
#include <sys/syscall.h>

#define TRACE_NULL                          0
#define TRACE_ERROR                         1
#define TRACE_INFO                          2
#define TRACE_DEBUG                         3

#define CURRENT_TRACE_LEVEL                 TRACE_INFO


#define PRINT_ERROR(fmt, args...)                                                               \
do {                                                                                            \
    if (CURRENT_TRACE_LEVEL >= TRACE_ERROR) {                                                   \
        printf("ERROR (func:%s line:%d SYS_gettid:%llu getpid:%llu): """                        \
            fmt, __func__, __LINE__, syscall(SYS_gettid), getpid(), ## args);                   \
    }                                                                                           \
} while (0)

#define PRINT_INFO(fmt, args...)                                                                \
do {                                                                                            \
    if (CURRENT_TRACE_LEVEL >= TRACE_INFO) {                                                    \
        printf("INFO (func:%s line:%d SYS_gettid:%llu getpid:%llu): """                         \
            fmt, __func__, __LINE__, syscall(SYS_gettid), getpid(), ## args);                   \
    }                                                                                           \
} while (0)

#define PRINT_DEBUG(fmt, args...)                                                               \
do {                                                                                            \
    if (CURRENT_TRACE_LEVEL >= TRACE_DEBUG) {                                                   \
        printf("DEBUG (func:%s line:%d SYS_gettid:%llu getpid:%llu): """                        \
            fmt, __func__, __LINE__, syscall(SYS_gettid), getpid(), ## args);                   \
    }                                                                                           \
} while (0)

//g++ -rdynamic
#define BACKTRACE_ARRAY_SIZE   32
static void dump_stack(void)
{
    int backtraceLength = 0;
    char** backtraceSymbols = NULL;

    void* backtraceArray[BACKTRACE_ARRAY_SIZE];
    backtraceLength = backtrace(backtraceArray, BACKTRACE_ARRAY_SIZE);
    backtraceSymbols = backtrace_symbols(backtraceArray, backtraceLength); // note: symbols are malloc'ed and need to be freed later

    std::string threadName = "current thread name: ";
    size_t name_size = getpagesize(); //sysconf(_SC_PAGESIZE)
    char *name = (char*)malloc(name_size);

    for(int i = 0; i < backtraceLength; i++) {
        char *begin_name = NULL, *begin_offset = NULL, *end_offset = 0;
        for (char *p = backtraceSymbols[i]; *p; ++p) {  // 利用了符号信息的格式
            if (*p == '(') {                            // 左括号
                begin_name = p;
            } else if (*p == '+' && begin_name) {       // 地址偏移符号
                begin_offset = p;
            } else if (*p == ')' && begin_offset) {     // 右括号
                end_offset = p;
                break;
            }
        }

        if (begin_name && begin_offset && end_offset ) {
            *begin_name++   = '\0';
            *begin_offset++ = '\0';
            *end_offset     = '\0';
            int status = -4; // 0 -1 -2 -3
            char *ret = abi::__cxa_demangle(begin_name, name, &name_size, &status); // may realloc
            if (0 == status) {
                assert(name == ret);
                PRINT_INFO("%s %s:%s+%s\n", threadName.c_str(), backtraceSymbols[i], name, begin_offset);
            } else {
                PRINT_INFO("%s %s:%s()+%s\n", threadName.c_str(), backtraceSymbols[i], begin_name, begin_offset);
            }
        } else {
            PRINT_INFO("%s %s\n", threadName.c_str(), backtraceSymbols[i]);
        }
    }

    free(name);
    free(backtraceSymbols);
}
#endif // debug.h
