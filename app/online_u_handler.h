//
// Created by lqy on 30/07/2019.
//

#ifndef MY_SGX_ONLINE_U_HANDLER_H
#define MY_SGX_ONLINE_U_HANDLER_H

#include "enclave_u.h"
#include "sgx_urts.h"
#include "app.h"
#include "utils.h"

struct online_u_args {
    const char *ca_hostname;
    const char *ca_port;
    const char *t_hostname;
    const char *t_port;
    const char *n;
    const char *snps_file;
};

int online_u_handler(struct online_u_args *arg);

#endif //MY_SGX_ONLINE_U_HANDLER_H
