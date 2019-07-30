//
// Created by lqy on 30/07/2019.
//

#include "offline_ca_handler.h"

void *offline_ca_handler(void *arg) {
    struct offline_ca_args *oargs = (struct offline_ca_args *) arg;
    struct offline_ca_args args = {0};

    //copy arguments onto thread's own stack
    memcpy(&args, oargs, sizeof(args));

    //finish copying arguments onto own stack and wait until main thread has called pthread_detach()
    pthread_barrier_wait(args.barrier);

    // declare enclave & return variables
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    sgx_status_t ecall_status, enclave_status;
    int updated, ret;
    ssize_t sret;
    int sockfd = args.sockfd;

    ////////////////////////////////////////////////
    // initialise enclave
    ////////////////////////////////////////////////
    enclave_status = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (enclave_status != SGX_SUCCESS) {
        error_print("Failed to initialise enclave");
        pthread_exit(NULL);
    }
    info_print("Enclave successfully initilised");

    // convert n to integer
    uint32_t n = (uint32_t) strtol(args.n, NULL, 10);

    // allocate memory for ws, Ws and d
    size_t ws_data_len = ws_size_from_n(n);
    size_t Ws_data_len = Ws_size_from_n(n);

    uint8_t *ws_data = (uint8_t *) calloc(ws_data_len, 1);
    uint8_t *Ws_data = (uint8_t *) calloc(Ws_data_len, 1);
    uint8_t *d_data = (uint8_t *) calloc(D_SIZE, 1);

    if (ws_data == NULL || Ws_data == NULL || d_data == NULL) {
        error_print("Failed to allocate memory");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(ws_data);
        free(Ws_data);
        free(d_data);

        pthread_exit(NULL);
    }

    // initialise common context
    ecall_status = ecall_common_initialise(eid, &ret, n);
    if (ecall_status != SGX_SUCCESS || ret < 0) {
        error_print("Failed to initialise common context");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(ws_data);
        free(Ws_data);
        free(d_data);

        pthread_exit(NULL);
    }

    // initialise offline CA context
    ecall_status = ecall_offline_ca_initialise(eid, &ret);
    if (ecall_status != SGX_SUCCESS || ret < 0) {
        error_print("Failed to initialise offline CA context");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(ws_data);
        free(Ws_data);
        free(d_data);

        pthread_exit(NULL);
    }

    // offline message 1: receive ws from T
    sret = tcp_read(sockfd, ws_data, ws_data_len);
    if (sret != ws_data_len) {
        error_print("Failed to receive ws from T");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(ws_data);
        free(Ws_data);
        free(d_data);

        pthread_exit(NULL);
    }

    // set ws and compute Ws
    ecall_status = ecall_offline_ca_set_ws_and_compute_Ws(eid, &ret, (uint32_t *) ws_data);
    if (ecall_status != SGX_SUCCESS || ret < 0) {
        error_print("Failed to set ws and compute Ws");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(ws_data);
        free(Ws_data);
        free(d_data);

        pthread_exit(NULL);
    }

    // get d and Ws
    ecall_status = ecall_offline_ca_get_d_and_Ws(eid, &ret, d_data, Ws_data, Ws_data_len);
    if (ecall_status != SGX_SUCCESS || ret < 0) {
        error_print("Failed to get d and Ws");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(ws_data);
        free(Ws_data);
        free(d_data);

        pthread_exit(NULL);
    }

    // offline message 2: send Ws to T
    sret = tcp_write(sockfd, Ws_data, Ws_data_len);
    if (sret != Ws_data_len) {
        error_print("Failed to send Ws to T");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(ws_data);
        free(Ws_data);
        free(d_data);

        pthread_exit(NULL);
    }

    // save d to file
    sret = save_file(D_FILE, d_data, D_SIZE);
    if (sret < 0) {
        error_print("Failed to save d to file");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(ws_data);
        free(Ws_data);
        free(d_data);

        pthread_exit(NULL);
    }
    info_print("d saved to file "
               D_FILE);

    ////////////////////////////////////////////////
    // destroy enclave
    ////////////////////////////////////////////////
    enclave_status = sgx_destroy_enclave(eid);
    if (enclave_status != SGX_SUCCESS) {
        error_print("Failed to destroy enclave");
        pthread_exit(NULL);
    }
    info_print("Enclave successfully destroyed");

    close(sockfd);
    free(ws_data);
    free(Ws_data);
    free(d_data);

    pthread_exit(NULL);
}