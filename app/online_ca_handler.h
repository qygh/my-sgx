//
// Created by lqy on 30/07/2019.
//

#ifndef MY_SGX_ONLINE_CA_HANDLER_H
#define MY_SGX_ONLINE_CA_HANDLER_H

#include "enclave_u.h"
#include "app.h"
#include "utils.h"
#include "debug.h"
#include "enclave.h"
#include "test.h"

struct online_ca_args {
    pthread_barrier_t *barrier;
    int sockfd;
    const char *n;
    const char *d_file;
};

void* online_ca_handler(void *arg);

#endif //MY_SGX_ONLINE_CA_HANDLER_H
