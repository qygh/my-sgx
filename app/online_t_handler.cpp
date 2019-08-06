//
// Created by lqy on 30/07/2019.
//

#include "online_t_handler.h"

void *online_t_handler(void *arg) {
    struct online_t_args *oargs = (struct online_t_args *) arg;
    struct online_t_args args = {0};

    // copy arguments onto thread's own stack
    memcpy(&args, oargs, sizeof(args));

    // finish copying arguments onto own stack and wait until main thread has called pthread_detach()
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

    // allocate memory for x, cts, res and result
    size_t x_data_len = X_SIZE;
    size_t cts_data_len = cts_size_from_n(n);

    uint8_t *x_data = (uint8_t *) calloc(x_data_len, 1);
    uint8_t *cts_data = (uint8_t *) calloc(cts_data_len, 1);
    uint8_t *res_data = (uint8_t *) calloc(RES_SIZE, 1);
    uint8_t *result_data = (uint8_t *) calloc(RESULT_SIZE, 1);

    if (x_data == NULL || cts_data == NULL || res_data == NULL || result_data == NULL) {
        error_print("Failed to allocate memory");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(x_data);
        free(cts_data);
        free(res_data);
        free(result_data);

        pthread_exit(NULL);
    }

    // load x from file
    sret = load_file_maxlen(args.x_file, x_data, x_data_len);
    if (sret < 0) {
        error_print("Failed to load x from file");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(x_data);
        free(cts_data);
        free(res_data);
        free(result_data);

        pthread_exit(NULL);
    }
    x_data_len = sret;

    // load cts from file
    sret = load_file_maxlen(args.cts_file, cts_data, cts_data_len);
    if (sret < 0) {
        error_print("Failed to load cts from file");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(x_data);
        free(cts_data);
        free(res_data);
        free(result_data);

        pthread_exit(NULL);
    }
    cts_data_len = sret;

    // initialise common context
    ecall_status = ecall_common_initialise(eid, &ret, n);
    if (ecall_status != SGX_SUCCESS || ret < 0) {
        error_print("Failed to initialise common context");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(x_data);
        free(cts_data);
        free(res_data);
        free(result_data);

        pthread_exit(NULL);
    }

    // initialise online T context
    ecall_status = ecall_online_t_initialise(eid, &ret, x_data, x_data_len);
    if (ecall_status != SGX_SUCCESS || ret < 0) {
        error_print("Failed to initialise online T context");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(x_data);
        free(cts_data);
        free(res_data);
        free(result_data);

        pthread_exit(NULL);
    }

    // unseal cts
    size_t cts_data_unsealed_len = cts_data_len - SEAL_ADDITIONAL_SIZE;
    uint8_t *cts_data_unsealed = (uint8_t *) calloc(cts_data_unsealed_len, 1);
    if (cts_data_unsealed == NULL) {
        error_print("Failed to allocate memory for unsealed cts");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(x_data);
        free(cts_data);
        free(res_data);
        free(result_data);

        pthread_exit(NULL);
    }

    ecall_status = ecall_online_t_unseal_cts(eid, &ret, cts_data, cts_data_len, cts_data_unsealed,
                                             cts_data_unsealed_len);
    if (ecall_status != SGX_SUCCESS || ret < 0) {
        error_print("Failed to unseal cts");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(x_data);
        free(cts_data);
        free(res_data);
        free(result_data);
        free(cts_data_unsealed);

        pthread_exit(NULL);
    }

    // online message 1: send cts to U
    info_print("Online message 1: send cts to U");
    sret = tcp_write(sockfd, cts_data_unsealed, cts_data_unsealed_len);
    if (sret != cts_data_unsealed_len) {
        error_print("Failed to send cts to U");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(x_data);
        free(cts_data);
        free(res_data);
        free(result_data);
        free(cts_data_unsealed);

        pthread_exit(NULL);
    }
    free(cts_data_unsealed);

    // online message 3: receive res from CA via U
    info_print("Online message 3: receive res from CA via U");
    sret = tcp_read(sockfd, res_data, RES_SIZE);
    if (sret != RES_SIZE) {
        error_print("Failed to receive res from CA via U");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(x_data);
        free(cts_data);
        free(res_data);
        free(result_data);

        pthread_exit(NULL);
    }

    // set res and get result
    ecall_status = ecall_online_t_set_res_and_get_result(eid, &ret, res_data, result_data);
    if (ecall_status != SGX_SUCCESS || ret < 0) {
        error_print("Failed to set res and get result");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(x_data);
        free(cts_data);
        free(res_data);
        free(result_data);

        pthread_exit(NULL);
    }

    // online message 4: send result to U
    info_print("Online message 4: send result to U");
    sret = tcp_write(sockfd, result_data, RESULT_SIZE);
    if (sret != RESULT_SIZE) {
        error_print("Failed to send result to U");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(x_data);
        free(cts_data);
        free(res_data);
        free(result_data);

        pthread_exit(NULL);
    }


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
    free(x_data);
    free(cts_data);
    free(res_data);
    free(result_data);

    pthread_exit(NULL);
}