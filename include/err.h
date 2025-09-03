#ifndef ERR_H
#define ERR_H

#define DATA_SUCCESS 0
#define ERR_pool_create (DATA_SUCCESS + 1)
#define ERR_thread_mutex_create (DATA_SUCCESS + 2)
#define ERR_thread_cond_create (DATA_SUCCESS + 3)
#define ERR_threadattr_create (DATA_SUCCESS + 4)
#define ERR_file_open (DATA_SUCCESS + 5)
#define ERR_thread_create (DATA_SUCCESS + 6)
#define ERR_yenc_encode (DATA_SUCCESS + 7)
#define ERR_yenc_decode (DATA_SUCCESS + 8)

typedef int data_status_t;

#endif
