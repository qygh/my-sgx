//
// Created by lqy on 30/07/2019.
//

#ifndef MY_SGX_OFFLINE_T_HANDLER_H
#define MY_SGX_OFFLINE_T_HANDLER_H

#include "enclave_u.h"
#include "sgx_urts.h"
#include "app.h"
#include "utils.h"

struct offline_t_args {
    const char *ca_hostname;
    const char *ca_port;
    const char *n;
    const char *w_file;
};

int offline_t_handler(struct offline_t_args *arg);

#endif //MY_SGX_OFFLINE_T_HANDLER_H
