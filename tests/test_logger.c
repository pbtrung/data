#include <apr_general.h>
#include <apr_pools.h>

#include "apr_logger.h"

int main() {
    apr_initialize();

    apr_pool_t *pool;
    apr_pool_create(&pool, NULL);

    apr_logger_t *logger;
    if (apr_logger_init(&logger, pool, "test.log") != APR_SUCCESS)
        return 1;

    apr_logger_shutdown(logger);
    apr_pool_destroy(pool);
    apr_terminate();
    return 0;
}
