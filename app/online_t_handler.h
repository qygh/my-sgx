//
// Created by lqy on 30/07/2019.
//

#ifndef MY_SGX_ONLINE_T_HANDLER_H
#define MY_SGX_ONLINE_T_HANDLER_H

#include "enclave_u.h"
#include "sgx_urts.h"
#include "app.h"
#include "utils.h"

struct online_t_args {
    pthread_barrier_t *barrier;
    int sockfd;
    const char *n;
    const char *x_file;
    const char *cts_file;
};

void* online_t_handler(void *arg);

#endif //MY_SGX_ONLINE_T_HANDLER_H
