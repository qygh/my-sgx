//
// Created by lqy on 24/07/19.
//

#ifndef MY_SGX_ENCLAVE_H
#define MY_SGX_ENCLAVE_H

#define EC_ORDER_BIT_SIZE 256

int ecall_common_initialise(uint32_t n);

int ecall_decode_result(const uint8_t *result_data, uint64_t *decoded_result);

int ecall_offline_t_initialise();

int ecall_offline_t_set_Ws_and_compute_cts(const uint8_t *Ws_data, size_t Ws_data_size);

int ecall_offline_t_get_x_and_cts(uint8_t *x_data, uint8_t *cts_data, size_t cts_data_size);

int ecall_offline_ca_initialise();

int ecall_offline_ca_set_ws_and_compute_Ws(uint32_t *ws);

int ecall_offline_ca_get_d_and_Ws(uint8_t *d_data, uint8_t *Ws_data, size_t Ws_data_size);

int ecall_online_t_initialise(const uint8_t *x_data);

int ecall_online_t_set_res_and_get_result(const uint8_t *res_data, uint8_t *result_data);

int ecall_online_u_initialise(const uint8_t *snps);

int ecall_online_u_set_cts_and_compute_ctres_pres_sres(const uint8_t *cts_data, size_t cts_data_size);

int ecall_online_u_get_ctres_pres_sres(uint8_t *ctres_data, uint64_t *pres_data, uint64_t *sres_data);

int ecall_online_ca_initialise(const uint8_t *d_data);

int ecall_online_ca_set_ctres_pres_sres_and_compute_res(const uint8_t *ctres_data, const uint64_t *pres_data,
                                                        const uint64_t *sres_data);

int ecall_online_ca_get_res(uint8_t *res_data);

#endif //MY_SGX_ENCLAVE_H
