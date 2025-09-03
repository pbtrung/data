#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <apr.h>
#include <apr_file_io.h>
#include <apr_ring.h>
#include <apr_strings.h>
#include <apr_thread_cond.h>
#include <apr_thread_mutex.h>
#include <apr_thread_proc.h>
#include <apr_time.h>

#include "apr_logger.h"

#define RING_CAPACITY 1024
#define MAX_BATCH 128
#define MAX_FLUSH_COUNT 128
#define MAX_FLUSH_INTERVAL 200

typedef struct log_item_t {
    APR_RING_ENTRY(log_item_t) link;

    apr_time_t ts;
    log_level_t level;
    int src_line;
    const char *file;
    const char *func;
    const char *msg;
    const char *formatted;
    apr_size_t len;
} log_item_t;

APR_RING_HEAD(log_ring_t, log_item_t);

struct apr_logger_t {
    apr_pool_t *pool;
    apr_pool_t *batch_pool;

    struct log_ring_t ring;
    int count;

    apr_thread_mutex_t *mutex;
    apr_thread_cond_t *cond;

    apr_thread_t *thread;
    apr_threadattr_t *attr;

    volatile int running;

    apr_file_t *file;

    int flush_count;
    apr_time_t last_flush;
    int max_batch;
    apr_interval_time_t flush_interval;

    unsigned long dropped;
};

static const char *level_str(log_level_t level) {
    switch (level) {
    case LOG_DEBUG:
        return "DEBUG";
    case LOG_INFO:
        return "INFO";
    case LOG_WARN:
        return "WARN";
    case LOG_ERROR:
        return "ERROR";
    default:
        return "UNKNOWN";
    }
}

static int ring_push(apr_logger_t *logger, log_item_t *item) {
    apr_thread_mutex_lock(logger->mutex);
    if (logger->count >= RING_CAPACITY) {
        logger->dropped++;
        apr_thread_mutex_unlock(logger->mutex);
        return -1;
    }

    APR_RING_INSERT_TAIL(&logger->ring, item, log_item_t, link);
    logger->count++;
    apr_thread_cond_signal(logger->cond);
    apr_thread_mutex_unlock(logger->mutex);
    return 0;
}

static int ring_pop_batch(apr_logger_t *logger, log_item_t **out,
                          int max_items) {
    int n = 0;
    apr_thread_mutex_lock(logger->mutex);
    while (!APR_RING_EMPTY(&logger->ring, log_item_t, link) && n < max_items) {
        log_item_t *it = APR_RING_FIRST(&logger->ring);
        APR_RING_REMOVE(it, link);
        out[n++] = it;
        logger->count--;
    }
    apr_thread_mutex_unlock(logger->mutex);
    return n;
}

static void flush_batch(apr_logger_t *logger, log_item_t **batch, int n) {
    if (n == 0)
        return;

    struct iovec iov[MAX_BATCH];
    apr_size_t total_len = 0;

    for (int i = 0; i < n; ++i) {
        iov[i].iov_base = (void *)batch[i]->formatted;
        iov[i].iov_len = batch[i]->len;
        total_len += batch[i]->len;
    }

    apr_size_t written = total_len;
    apr_file_writev(logger->file, iov, n, &written);

    logger->flush_count += n;
    apr_time_t now = apr_time_now();
    if (logger->flush_count >= MAX_FLUSH_COUNT ||
        (now - logger->last_flush) >= logger->flush_interval) {
        apr_file_flush(logger->file);
        logger->flush_count = 0;
        logger->last_flush = now;
        apr_pool_clear(logger->batch_pool);
    }
}

static void *APR_THREAD_FUNC logger_thread(apr_thread_t *t, void *data) {
    apr_logger_t *logger = data;
    log_item_t *batch[MAX_BATCH];

    while (logger->running) {
        apr_thread_mutex_lock(logger->mutex);
        if (logger->count == 0 && logger->running) {
            apr_time_t deadline = apr_time_now() + logger->flush_interval;
            apr_thread_cond_timedwait(logger->cond, logger->mutex, deadline);
        }
        apr_thread_mutex_unlock(logger->mutex);

        int n = ring_pop_batch(logger, batch, logger->max_batch);
        flush_batch(logger, batch, n);
    }

    int n;
    while ((n = ring_pop_batch(logger, batch, logger->max_batch)) > 0)
        flush_batch(logger, batch, n);

    apr_file_flush(logger->file);
    return NULL;
}

data_status_t apr_logger_init(apr_logger_t **out, apr_pool_t *parent_pool,
                              const char *filename) {
    if (!parent_pool || !filename)
        return APR_EINVAL;

    apr_pool_t *pool;
    apr_status_t rv = apr_pool_create(&pool, parent_pool);
    if (rv != APR_SUCCESS)
        return ERR_pool_create;

    apr_pool_t *batch_pool;
    rv = apr_pool_create(&batch_pool, pool);
    if (rv != APR_SUCCESS) {
        apr_pool_destroy(pool);
        return ERR_pool_create;
    }

    apr_logger_t *logger = apr_pcalloc(pool, sizeof(*logger));
    logger->pool = pool;
    logger->batch_pool = batch_pool;

    APR_RING_INIT(&logger->ring, log_item_t, link);
    logger->count = 0;

    rv =
        apr_thread_mutex_create(&logger->mutex, APR_THREAD_MUTEX_DEFAULT, pool);
    if (rv != APR_SUCCESS) {
        apr_pool_destroy(pool);
        return ERR_thread_mutex_create;
    }

    rv = apr_thread_cond_create(&logger->cond, pool);
    if (rv != APR_SUCCESS) {
        apr_pool_destroy(pool);
        return ERR_thread_cond_create;
    }

    rv = apr_threadattr_create(&logger->attr, pool);
    if (rv != APR_SUCCESS) {
        apr_pool_destroy(pool);
        return ERR_threadattr_create;
    }

    rv = apr_file_open(&logger->file, filename,
                       APR_FOPEN_CREATE | APR_FOPEN_APPEND | APR_FOPEN_WRITE,
                       APR_OS_DEFAULT, pool);
    if (rv != APR_SUCCESS) {
        apr_pool_destroy(pool);
        return ERR_file_open;
    }

    logger->running = 1;
    logger->flush_count = 0;
    logger->last_flush = apr_time_now();
    logger->max_batch = MAX_BATCH;
    logger->flush_interval = apr_time_from_msec(MAX_FLUSH_INTERVAL);
    logger->dropped = 0;

    rv = apr_thread_create(&logger->thread, logger->attr, logger_thread, logger,
                           pool);
    if (rv != APR_SUCCESS) {
        apr_file_close(logger->file);
        apr_pool_destroy(pool);
        return ERR_thread_create;
    }

    *out = logger;
    return DATA_SUCCESS;
}

void apr_logger_shutdown(apr_logger_t *logger) {
    if (!logger)
        return;

    apr_status_t trv;
    apr_thread_mutex_lock(logger->mutex);
    logger->running = 0;
    apr_thread_cond_signal(logger->cond);
    apr_thread_mutex_unlock(logger->mutex);

    apr_thread_join(&trv, logger->thread);

    if (logger->file) {
        apr_file_close(logger->file);
        logger->file = NULL;
    }

    if (logger->pool)
        apr_pool_destroy(logger->pool);
}

void apr_logger_log(apr_logger_t *logger, log_level_t level, const char *file,
                    int line, const char *func, const char *fmt, ...) {
    if (!logger || !logger->running)
        return;

    apr_pool_t *p = logger->batch_pool;

    log_item_t *tmp = apr_palloc(p, sizeof(*tmp));
    if (!tmp)
        return;

    tmp->ts = apr_time_now();
    tmp->level = level;
    tmp->src_line = line;

    tmp->file = apr_pstrdup(p, file ? file : "?");
    tmp->func = apr_pstrdup(p, func ? func : "?");

    char mbuf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(mbuf, sizeof(mbuf), fmt, args);
    va_end(args);
    tmp->msg = apr_pstrdup(p, mbuf);

    char timestr[64];
    apr_time_exp_t tm;
    apr_time_exp_lt(&tm, tmp->ts);
    int ms = (int)((tmp->ts / 1000) % 1000);
    snprintf(timestr, sizeof(timestr), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
             tm.tm_min, tm.tm_sec, ms);

    tmp->formatted = apr_psprintf(p, "[%s] %s (%s:%d:%s) %s\n", timestr,
                                  level_str(tmp->level), tmp->file,
                                  tmp->src_line, tmp->func, tmp->msg);

    tmp->len = strlen(tmp->formatted);

    (void)ring_push(logger, tmp);
}
