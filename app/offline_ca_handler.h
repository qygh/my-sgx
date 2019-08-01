//
// Created by lqy on 30/07/2019.
//

#ifndef MY_SGX_OFFLINE_CA_HANDLER_H
#define MY_SGX_OFFLINE_CA_HANDLER_H

#include "enclave_u.h"
#include "sgx_urts.h"
#include "app.h"
#include "utils.h"

struct offline_ca_args {
    pthread_barrier_t *barrier;
    int sockfd;
    const char *n;
};

void* offline_ca_handler(void *arg);

#endif //MY_SGX_OFFLINE_CA_HANDLER_H
