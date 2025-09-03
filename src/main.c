#include <apr_general.h>
#include <apr_pools.h>

#include "apr_logger.h"
#include "err.h"

int main() {
    apr_initialize();

    apr_pool_t *pool;
    apr_pool_create(&pool, NULL);

    apr_logger_t *logger;
    data_status_t rv = apr_logger_init(&logger, pool, "test.log");
    if (rv != DATA_SUCCESS)
        return rv;

    apr_logger_shutdown(logger);
    apr_pool_destroy(pool);
    apr_terminate();
    return DATA_SUCCESS;
}
