//
// Created by lqy on 30/07/2019.
//

#include "online_ca_handler.h"

void *online_ca_handler(void *arg) {
    struct online_ca_args *oargs = (struct online_ca_args *) arg;
    struct online_ca_args args = {0};

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

    // allocate memory for d, ctres, pres, sres and res
    uint8_t *d_data = (uint8_t *) calloc(D_SIZE, 1);
    uint8_t *ctres_data = (uint8_t *) calloc(CTRES_SIZE, 1);
    uint8_t *pres_data = (uint8_t *) calloc(PRES_SIZE, 1);
    uint8_t *sres_data = (uint8_t *) calloc(SRES_SIZE, 1);
    uint8_t *res_data = (uint8_t *) calloc(RES_SIZE, 1);

    if (d_data == NULL || ctres_data == NULL || pres_data == NULL || sres_data == NULL || res_data == NULL) {
        error_print("Failed to allocate memory");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(d_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(res_data);

        pthread_exit(NULL);
    }

    // load d from file
    sret = load_file(args.d_file, d_data, D_SIZE);
    if (sret < 0) {
        error_print("Failed to load d from file");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(d_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(res_data);

        pthread_exit(NULL);
    }

    // initialise common context
    ecall_status = ecall_common_initialise(eid, &ret, n);
    if (ecall_status != SGX_SUCCESS || ret < 0) {
        error_print("Failed to initialise common context");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(d_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(res_data);

        pthread_exit(NULL);
    }

    // initialise online CA context
    ecall_status = ecall_online_ca_initialise(eid, &ret, d_data);
    if (ecall_status != SGX_SUCCESS || ret < 0) {
        error_print("Failed to initialise online CA context");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(d_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(res_data);

        pthread_exit(NULL);
    }

    // online message 2: receive ctres, pres and sres from U
    info_print("Online message 2: receive ctres, pres and sres from U");
    sret = tcp_read(sockfd, ctres_data, CTRES_SIZE);
    if (sret != CTRES_SIZE) {
        error_print("Failed to receive ctres from U");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(d_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(res_data);

        pthread_exit(NULL);
    }
    sret = tcp_read(sockfd, pres_data, PRES_SIZE);
    if (sret != PRES_SIZE) {
        error_print("Failed to receive pres from U");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(d_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(res_data);

        pthread_exit(NULL);
    }
    sret = tcp_read(sockfd, sres_data, SRES_SIZE);
    if (sret != SRES_SIZE) {
        error_print("Failed to receive sres from U");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(d_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(res_data);

        pthread_exit(NULL);
    }

    // set ctres, pres, sres and compute res
    ecall_status = ecall_online_ca_set_ctres_pres_sres_and_compute_res(eid, &ret, ctres_data, (uint64_t *) pres_data,
                                                                       (uint64_t *) sres_data);
    if (ecall_status != SGX_SUCCESS || ret < 0) {
        error_print("Failed to set ctres, pres, sres and compute res");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(d_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(res_data);

        pthread_exit(NULL);
    }

    // get res
    ecall_status = ecall_online_ca_get_res(eid, &ret, res_data);
    if (ecall_status != SGX_SUCCESS || ret < 0) {
        error_print("Failed to get res");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(d_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(res_data);

        pthread_exit(NULL);
    }

    // online message 3: send res to T via U
    info_print("Online message 3: send res to T via U");
    sret = tcp_write(sockfd, res_data, RES_SIZE);
    if (sret != RES_SIZE) {
        error_print("Failed to send res to T via U");

        sgx_destroy_enclave(eid);
        close(sockfd);
        free(d_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(res_data);

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
    free(d_data);
    free(ctres_data);
    free(pres_data);
    free(sres_data);
    free(res_data);

    pthread_exit(NULL);


}