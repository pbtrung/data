#ifndef APR_LOGGER_H
#define APR_LOGGER_H

#include <apr.h>
#include <apr_file_io.h>
#include <apr_thread_proc.h>
#include <stdarg.h>
#include <string.h>

#include "err.h"

typedef enum { LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR } log_level_t;

typedef struct apr_logger_t apr_logger_t;

static inline const char *get_filename(const char *path) {
    const char *last_slash = strrchr(path, '/');
    return last_slash ? last_slash + 1 : path;
}

data_status_t apr_logger_init(apr_logger_t **logger, apr_pool_t *parent_pool,
                              const char *filename);

void apr_logger_shutdown(apr_logger_t *logger);

void apr_logger_log(apr_logger_t *logger, log_level_t level, const char *file,
                    int line, const char *func, const char *fmt, ...);

#define LOG_DEBUG(logger, fmt, ...)                                            \
    apr_logger_log(logger, LOG_DEBUG, get_filename(__FILE__), __LINE__,        \
                   __func__, fmt, ##__VA_ARGS__)
#define LOG_INFO(logger, fmt, ...)                                             \
    apr_logger_log(logger, LOG_INFO, get_filename(__FILE__), __LINE__,         \
                   __func__, fmt, ##__VA_ARGS__)
#define LOG_WARN(logger, fmt, ...)                                             \
    apr_logger_log(logger, LOG_WARN, get_filename(__FILE__), __LINE__,         \
                   __func__, fmt, ##__VA_ARGS__)
#define LOG_ERROR(logger, fmt, ...)                                            \
    apr_logger_log(logger, LOG_ERROR, get_filename(__FILE__), __LINE__,        \
                   __func__, fmt, ##__VA_ARGS__)

#endif
