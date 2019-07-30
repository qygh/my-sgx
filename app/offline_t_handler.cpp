//
// Created by lqy on 30/07/2019.
//

#include "offline_t_handler.h"

int offline_t_handler(struct offline_t_args *arg) {
    struct offline_t_args *args = arg;

    // declare enclave & return variables
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    sgx_status_t ecall_status, enclave_status;
    int updated, ret;
    ssize_t sret;
    int sockfd;

    ////////////////////////////////////////////////
    // initialise enclave
    ////////////////////////////////////////////////
    enclave_status = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (enclave_status != SGX_SUCCESS) {
        error_print("Failed to initialise enclave");
        return -1;
    }
    info_print("Enclave successfully initilised");

    // create socket and connect to CA
    sockfd = create_tcp_client_socket(args->ca_hostname, args->ca_port);
    if (sockfd < 0) {
        error_print("Failed to create client socket");

        sgx_destroy_enclave(eid);

        return -1;
    }

    // convert n to integer
    uint32_t n = (uint32_t) strtol(args->n, NULL, 10);

    // allocate memory for ws, Ws, x and cts
    size_t ws_data_len = ws_size_from_n(n);
    size_t Ws_data_len = Ws_size_from_n(n);
    size_t cts_data_len = cts_size_from_n(n);

    uint8_t *ws_data = (uint8_t *) calloc(ws_data_len, 1);
    uint8_t *Ws_data = (uint8_t *) calloc(Ws_data_len, 1);
    uint8_t *x_data = (uint8_t *) calloc(X_SIZE, 1);
    uint8_t *cts_data = (uint8_t *) calloc(cts_data_len, 1);

    if (ws_data == NULL || Ws_data == NULL || x_data == NULL || cts_data == NULL) {
        error_print("Failed to allocate memory");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(ws_data);
        free(Ws_data);
        free(x_data);
        free(cts_data);

        return -1;
    }

    // load ws from file
    sret = load_file(args->w_file, ws_data, ws_data_len);
    if (sret < 0) {
        error_print("Failed to load ws from file");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(ws_data);
        free(Ws_data);
        free(x_data);
        free(cts_data);

        return -1;
    }

    // initialise common context
    ecall_status = ecall_common_initialise(eid, &ret, n);
    if (ecall_status != SGX_SUCCESS || ret < 0) {
        error_print("Failed to initialise common context");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(ws_data);
        free(Ws_data);
        free(x_data);
        free(cts_data);

        return -1;
    }

    // initialise offline T context
    ecall_status = ecall_offline_t_initialise(eid, &ret);
    if (ecall_status != SGX_SUCCESS || ret < 0) {
        error_print("Failed to initialise offline T context");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(ws_data);
        free(Ws_data);
        free(x_data);
        free(cts_data);

        return -1;
    }

    // offline message 1: send ws to CA
    sret = tcp_write(sockfd, ws_data, ws_data_len);
    if (sret != ws_data_len) {
        error_print("Failed to send ws to CA");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(ws_data);
        free(Ws_data);
        free(x_data);
        free(cts_data);

        return -1;
    }

    // offline message 2: receive Ws from CA
    sret = tcp_read(sockfd, Ws_data, Ws_data_len);
    if (sret != Ws_data_len) {
        error_print("Failed to receive Ws from CA");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(ws_data);
        free(Ws_data);
        free(x_data);
        free(cts_data);

        return -1;
    }

    // set Ws and compute cts
    ecall_status = ecall_offline_t_set_Ws_and_compute_cts(eid, &ret, Ws_data, Ws_data_len);
    if (ecall_status != SGX_SUCCESS || ret < 0) {
        error_print("Failed to set Ws and compute cts");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(ws_data);
        free(Ws_data);
        free(x_data);
        free(cts_data);

        return -1;
    }

    // get x and cts
    ecall_status = ecall_offline_t_get_x_and_cts(eid, &ret, x_data, cts_data, cts_data_len);
    if (ecall_status != SGX_SUCCESS || ret < 0) {
        error_print("Failed to get x and cts");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(ws_data);
        free(Ws_data);
        free(x_data);
        free(cts_data);

        return -1;
    }

    // save x to file
    sret = save_file(X_FILE, x_data, X_SIZE);
    if (sret < 0) {
        error_print("Failed to save x to file");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(ws_data);
        free(Ws_data);
        free(x_data);
        free(cts_data);

        return -1;
    }
    info_print("x saved to file "
               X_FILE);

    // save cts to file
    sret = save_file(CTS_FILE, cts_data, cts_data_len);
    if (sret < 0) {
        error_print("Failed to save cts to file");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(ws_data);
        free(Ws_data);
        free(x_data);
        free(cts_data);

        return -1;
    }
    info_print("cts saved to file "
               CTS_FILE);


    ////////////////////////////////////////////////
    // destroy enclave
    ////////////////////////////////////////////////
    enclave_status = sgx_destroy_enclave(eid);
    if (enclave_status != SGX_SUCCESS) {
        error_print("Failed to destroy enclave");
        return -1;
    }
    info_print("Enclave successfully destroyed");

    close(sockfd);
    free(ws_data);
    free(Ws_data);
    free(x_data);
    free(cts_data);

    return 0;
}