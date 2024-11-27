/**
 * @file log.h
 * @author zishu (zishuzy@gmail.com)
 * @brief Simple logger
 * @version 0.1
 * @date 2023-12-18
 *
 * @copyright Copyright (c) 2023
 *
 */
#ifndef LOG_LOG
#define LOG_LOG

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <string.h>

#define LOG_VERBOSE(fp, level, fmt, ...)                                            \
    do {                                                                            \
        struct timeval tv_now;                                                      \
        struct tm tm_now;                                                           \
        char time_str_1[32] = {0};                                                  \
        char time_str_2[64] = {0};                                                  \
        gettimeofday(&tv_now, NULL);                                                \
        strftime(time_str_1, 32, "%Y-%m-%d %H:%M:%S",                               \
                 localtime_r((const time_t *)&tv_now.tv_sec, &tm_now));             \
        snprintf(time_str_2, 64, "%s.%.06ld", time_str_1, (long)tv_now.tv_usec);    \
        fprintf(fp, "%s|%s:[%d:%ld][%s:%d] " fmt "\n", level, time_str_2, getpid(), \
                syscall(SYS_gettid), __FUNCTION__, __LINE__, ##__VA_ARGS__);        \
    } while (0);

#ifdef DEBUG
    #define LOG_DEBUG(fmt, ...) LOG_VERBOSE(stdout, "D", fmt, ##__VA_ARGS__)
#else
    #define LOG_DEBUG(fmt, ...)
#endif

#define LOG_INFO(fmt, ...)  LOG_VERBOSE(stdout, "I", fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  LOG_VERBOSE(stdout, "W", fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) LOG_VERBOSE(stdout, "E", fmt, ##__VA_ARGS__)

#define BOOL_STR(v)    v ? "true" : "false"
#define BOOL_RESULT(v) v ? "success" : "failure"

#endif /* LOG_LOG */
