//
// Created by lqy on 30/07/2019.
//

#include "online_u_handler.h"

int online_u_handler(struct online_u_args *arg) {
    struct online_u_args *args = arg;

    // declare enclave & return variables
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    sgx_status_t ecall_status, enclave_status;
    int updated, ret;
    ssize_t sret;
    int sockfd_t, sockfd_ca;

    ////////////////////////////////////////////////
    // initialise enclave
    ////////////////////////////////////////////////
    enclave_status = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (enclave_status != SGX_SUCCESS) {
        error_print("Failed to initialise enclave");
        return -1;
    }
    info_print("Enclave successfully initilised");

    // create socket and connect to T
    sockfd_t = create_tcp_client_socket(args->t_hostname, args->t_port);
    if (sockfd_t < 0) {
        error_print("Failed to create client socket to T");

        sgx_destroy_enclave(eid);

        return -1;
    }

    // create socket and connect to CA
    sockfd_ca = create_tcp_client_socket(args->ca_hostname, args->ca_port);
    if (sockfd_ca < 0) {
        error_print("Failed to create client socket to CA");

        sgx_destroy_enclave(eid);
        close(sockfd_t);

        return -1;
    }

    // convert n to integer
    uint32_t n = (uint32_t) strtol(args->n, NULL, 10);

    // allocate memory for snps, cts, ctres, pres and sres
    size_t snps_data_len = snps_size_from_n(n);
    size_t cts_data_len = cts_size_from_n(n);

    uint8_t *snps_data = (uint8_t *) calloc(snps_data_len, 1);
    uint8_t *cts_data = (uint8_t *) calloc(cts_data_len, 1);
    uint8_t *ctres_data = (uint8_t *) calloc(CTRES_SIZE, 1);
    uint8_t *pres_data = (uint8_t *) calloc(PRES_SIZE, 1);
    uint8_t *sres_data = (uint8_t *) calloc(SRES_SIZE, 1);
    uint8_t *result_data = (uint8_t *) calloc(RESULT_SIZE, 1);

    if (snps_data == NULL || cts_data == NULL || ctres_data == NULL || pres_data == NULL || sres_data == NULL ||
        result_data == NULL) {
        error_print("Failed to allocate memory");

        sgx_destroy_enclave(eid);
        close(sockfd_t);
        close(sockfd_ca);
        free(snps_data);
        free(cts_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(result_data);

        return -1;
    }

    // load snps from file
    sret = load_file(args->snps_file, snps_data, snps_data_len);
    if (sret < 0) {
        error_print("Failed to load snps from file");

        sgx_destroy_enclave(eid);
        close(sockfd_t);
        close(sockfd_ca);
        free(snps_data);
        free(cts_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(result_data);

        return -1;
    }

    // initialise common context
    ecall_status = ecall_common_initialise(eid, &ret, n);
    if (ecall_status != SGX_SUCCESS || ret < 0) {
        error_print("Failed to initialise common context");

        sgx_destroy_enclave(eid);
        close(sockfd_t);
        close(sockfd_ca);
        free(snps_data);
        free(cts_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(result_data);

        return -1;
    }

    // initialise online U context
    ecall_status = ecall_online_u_initialise(eid, &ret, snps_data);
    if (ecall_status != SGX_SUCCESS || ret < 0) {
        error_print("Failed to initialise online U context");

        sgx_destroy_enclave(eid);
        close(sockfd_t);
        close(sockfd_ca);
        free(snps_data);
        free(cts_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(result_data);

        return -1;
    }

    // online message 1: receive cts from T
    info_print("Online message 1: receive cts from T");
    sret = tcp_read(sockfd_t, cts_data, cts_data_len);
    if (sret != cts_data_len) {
        error_print("Failed to receive cts from T");

        sgx_destroy_enclave(eid);
        close(sockfd_t);
        close(sockfd_ca);
        free(snps_data);
        free(cts_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(result_data);

        return -1;
    }

    // set cts and compute ctres, pres and sres
    ecall_status = ecall_online_u_set_cts_and_compute_ctres_pres_sres(eid, &ret, cts_data, cts_data_len);
    if (ecall_status != SGX_SUCCESS || ret < 0) {
        error_print("Failed to set cts and compute ctres, pres and sres");

        sgx_destroy_enclave(eid);
        close(sockfd_t);
        close(sockfd_ca);
        free(snps_data);
        free(cts_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(result_data);

        return -1;
    }

    // get ctres, pres and sres
    ecall_status = ecall_online_u_get_ctres_pres_sres(eid, &ret, ctres_data, (uint64_t *) pres_data,
                                                      (uint64_t *) sres_data);
    if (ecall_status != SGX_SUCCESS || ret < 0) {
        error_print("Failed to get ctres, pres and sres");

        sgx_destroy_enclave(eid);
        close(sockfd_t);
        close(sockfd_ca);
        free(snps_data);
        free(cts_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(result_data);

        return -1;
    }

    // online message 2: send ctres, pres and sres to CA
    info_print("Online message 2: send ctres, pres and sres to CA");
    sret = tcp_write(sockfd_ca, ctres_data, CTRES_SIZE);
    if (sret != CTRES_SIZE) {
        error_print("Failed to send ctres to CA");

        sgx_destroy_enclave(eid);
        close(sockfd_t);
        close(sockfd_ca);
        free(snps_data);
        free(cts_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(result_data);

        return -1;
    }
    sret = tcp_write(sockfd_ca, pres_data, PRES_SIZE);
    if (sret != PRES_SIZE) {
        error_print("Failed to send pres to CA");

        sgx_destroy_enclave(eid);
        close(sockfd_t);
        close(sockfd_ca);
        free(snps_data);
        free(cts_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(result_data);

        return -1;
    }
    sret = tcp_write(sockfd_ca, sres_data, SRES_SIZE);
    if (sret != SRES_SIZE) {
        error_print("Failed to send sres to CA");

        sgx_destroy_enclave(eid);
        close(sockfd_t);
        close(sockfd_ca);
        free(snps_data);
        free(cts_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(result_data);

        return -1;
    }

    // online message 3: receive res from CA and forward it to T
    info_print("Online message 3: receive res from CA and forward it to T");
    uint8_t res[RES_SIZE] = {0};
    sret = tcp_read(sockfd_ca, res, RES_SIZE);
    if (sret != RES_SIZE) {
        error_print("Failed to receive res from CA");

        sgx_destroy_enclave(eid);
        close(sockfd_t);
        close(sockfd_ca);
        free(snps_data);
        free(cts_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(result_data);

        return -1;
    }
    sret = tcp_write(sockfd_t, res, RES_SIZE);
    if (sret != RES_SIZE) {
        error_print("Failed to forward res to T");

        sgx_destroy_enclave(eid);
        close(sockfd_t);
        close(sockfd_ca);
        free(snps_data);
        free(cts_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(result_data);

        return -1;
    }

    // online message 4: receive result from T
    info_print("Online message 4: receive result from T");
    sret = tcp_read(sockfd_t, result_data, RESULT_SIZE);
    if (sret != RESULT_SIZE) {
        error_print("Failed to receive result from T");

        sgx_destroy_enclave(eid);
        close(sockfd_t);
        close(sockfd_ca);
        free(snps_data);
        free(cts_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(result_data);

        return -1;
    }

    // save result to file
    sret = save_file(RESULT_FILE, result_data, RESULT_SIZE);
    if (sret < 0) {
        error_print("Failed to save result to file");

        sgx_destroy_enclave(eid);
        close(sockfd_t);
        close(sockfd_ca);
        free(snps_data);
        free(cts_data);
        free(ctres_data);
        free(pres_data);
        free(sres_data);
        free(result_data);

        return -1;
    }
    info_print("result saved to file "
               RESULT_FILE);


    ////////////////////////////////////////////////
    // destroy enclave
    ////////////////////////////////////////////////
    enclave_status = sgx_destroy_enclave(eid);
    if (enclave_status != SGX_SUCCESS) {
        error_print("Failed to destroy enclave");
        return -1;
    }
    info_print("Enclave successfully destroyed");

    close(sockfd_t);
    close(sockfd_ca);
    free(snps_data);
    free(cts_data);
    free(ctres_data);
    free(pres_data);
    free(sres_data);
    free(result_data);

    return 0;
}