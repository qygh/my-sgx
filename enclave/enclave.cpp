/*
 * Copyright 2018 Alberto Sonnino
 * 
 * This file is part of SGX-WALLET.
 * 
 * SGX-WALLET is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * SGX-WALLET is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with SGX-WALLET.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "enclave_t.h"
#include "string.h"
#include "my_enclave.h"

#include "sgx_tseal.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "stdio.h"
#include "ipp/ippcp.h"

static int hello = 0;

/*
 * T : Testing Facility
 * U : User
 * CA: Certification Authority
 */

/*
 * Structure for common context
 */
struct common_context {
    // E: Elliptic curve
    int ec_context_size;
    int ec_order_bit_size;
    int ec_order_size;
    int ec_order_u32_size;
    IppsECCPState *E;

    // q: Big number
    int bn_context_size;
    IppsBigNumState *q;

    // G: Point
    int point_context_size;
    IppsECCPPointState *G;

    // n: Int (32 bits)
    uint32_t n;
};

/*
 * Structure for offline T context
 */
struct offline_t_context {
    // ws: Array of big numbers
    //IppsBigNumState **ws;

    // x: Big number
    IppsBigNumState *x;

    // Ws: Array of points
    IppsECCPPointState **Ws;

    // cts: Array of pair of points
    IppsECCPPointState **cts;
};

/*
 * Structure for offline CA context
 */
struct offline_ca_context {
    // ws: Array of big numbers
    //IppsBigNumState **ws;

    // d: Big number
    IppsBigNumState *d;

    // e: Big number
    IppsBigNumState *e;

    // Ws: Array of points
    IppsECCPPointState **Ws;
};

/*
 * Structure for online T context
 */
struct online_t_context {
    // x: Big number
    IppsBigNumState *x;

    // cts: Array of pair of points
    //IppsECCPPointState **cts;

    // res: Pair of points
    IppsECCPPointState *res[2];

    // result: Point
    //IppsECCPPointState *result;
};

/*
 * Structure for online U context
 */
struct online_u_context {
    // snps: Array of Bytes (8 bits)
    uint8_t *snps;

    // cts: Array of pair of points
    //IppsECCPPointState **cts;

    // ctres: Pair of points
    IppsECCPPointState *ctres[2];

    // pres: Long (64 bits)
    uint64_t pres;

    // sres: Long (64 bits)
    uint64_t sres;

    // result: Point
    //IppsECCPPointState *result;
};

/*
 * Structure for online CA context
 */
struct online_ca_context {
    // d: Big number
    IppsBigNumState *d;

    // ctres: Pair of points
    //IppsECCPPointState **ctres;

    // pres: Long (64 bits)
    //uint64_t pres;

    // sres: Long (64 bits)
    //uint64_t sres;

    // res: Pair of points
    IppsECCPPointState *res[2];
};

/*
 * Global structures
 */
static struct common_context context_common = {0};

static struct offline_t_context context_offline_t = {0};

static struct offline_ca_context context_offline_ca = {0};

static struct online_t_context context_online_t = {0};

static struct online_u_context context_online_u = {0};

static struct online_ca_context context_online_ca = {0};

static int test_printpoint(IppsECCPPointState *P);

static int test_printbn(IppsBigNumState *d);

/*
 * Operations for BigNum and Point
 */
static IppsBigNumState *bn_create_state(struct common_context *common); //Done

static IppsBigNumState *bn_create_state_double_size(struct common_context *common); //Done

static int
bn_set_value(struct common_context *common, IppsBigNumState *number, int u32_size, const uint32_t *value); //Done

static int bn_set_value_u32(struct common_context *common, IppsBigNumState *number, uint32_t value); //Done

static int bn_set_value_u64(struct common_context *common, IppsBigNumState *number, uint64_t value); //Done

static int bn_set_value_random(struct common_context *common, IppsBigNumState *number); //Done

static IppsECCPPointState *point_create_state(struct common_context *common); //Done

static int
point_mul_scalar_neg(struct common_context *common, const IppsECCPPointState *point, const IppsBigNumState *scalar,
                     IppsECCPPointState *result); //Done

/*
 * Common input: E, q, G, n
 */
int ecall_common_initialise(uint32_t n); //Done

static int common_initialise(struct common_context *common, uint32_t n); //Done

/*
 * Decode result by brute forcing discrete logarithms
 */
int ecall_decode_result(const uint8_t *result_data, uint64_t *decoded_result); // Done

static int decode_result(struct common_context *common, const uint8_t *result_data, uint64_t *decoded_result); // Done

/*
 * Offline operations for T
 */
int ecall_offline_t_initialise(); //Done

static int offline_t_initialise(struct common_context *common, struct offline_t_context *offline_t); //Done

int ecall_offline_t_set_Ws_and_compute_cts(const uint8_t *Ws_data, size_t Ws_data_size); //Done

static int offline_t_set_Ws_and_compute_cts(struct common_context *common, struct offline_t_context *offline_t,
                                            const uint8_t *Ws_data, const size_t Ws_data_size); //Done

int ecall_offline_t_get_x_and_cts(uint8_t *x_data_sealed, size_t *x_data_sealed_size, uint8_t *cts_data_sealed,
                                  size_t *cts_data_sealed_size); //Done

static int
offline_t_get_x_and_cts(struct common_context *common, struct offline_t_context *offline_t, uint8_t *x_data_sealed,
                        size_t *x_data_sealed_size,
                        uint8_t *cts_data_sealed, size_t *cts_data_sealed_size); //Done

/*
 * Offline operations for CA
 */
int ecall_offline_ca_initialise(); //Done

static int offline_ca_initialise(struct common_context *common, struct offline_ca_context *offline_ca); //Done

int ecall_offline_ca_set_ws_and_compute_Ws(uint32_t *ws); //Done

static int
offline_ca_set_ws_and_compute_Ws(struct common_context *common, struct offline_ca_context *offline_ca,
                                 uint32_t *ws); //Done

int ecall_offline_ca_get_d_and_Ws(uint8_t *d_data_sealed, size_t *d_data_sealed_size, uint8_t *Ws_data,
                                  size_t Ws_data_size); //Done

static int
offline_ca_get_d_and_Ws(struct common_context *common, struct offline_ca_context *offline_ca, uint8_t *d_data_sealed,
                        size_t *d_data_sealed_size,
                        uint8_t *Ws_data, size_t Ws_data_size); //Done

/*
 * Online operations for T
 */
int ecall_online_t_initialise(const uint8_t *x_data_sealed, size_t x_data_sealed_size); //Done

static int
online_t_initialise(struct common_context *common, struct online_t_context *online_t, const uint8_t *x_data_sealed,
                    size_t x_data_sealed_size); //Done

int ecall_online_t_unseal_cts(const uint8_t *cts_data_sealed, size_t cts_data_sealed_size, uint8_t *cts_data,
                              size_t cts_data_size); //Done

static int
online_t_unseal_cts(struct common_context *common, struct online_t_context *online_t, const uint8_t *cts_data_sealed,
                    size_t cts_data_sealed_size, uint8_t *cts_data,
                    size_t cts_data_size); //Done

int ecall_online_t_set_res_and_get_result(const uint8_t *res_data, uint8_t *result_data); //Done

static int online_t_set_res_and_get_result(struct common_context *common, struct online_t_context *online_t,
                                           const uint8_t *res_data, uint8_t *result_data); //Done

/*
 * Online operations for U
 */
int ecall_online_u_initialise(const uint8_t *snps); //Done

static int
online_u_initialise(struct common_context *common, struct online_u_context *online_u, const uint8_t *snps); //Done

int ecall_online_u_set_cts_and_compute_ctres_pres_sres(const uint8_t *cts_data, size_t cts_data_size); //Done

static int
online_u_set_cts_and_compute_ctres_pres_sres(struct common_context *common, struct online_u_context *online_u,
                                             const uint8_t *cts_data, size_t cts_data_size); //Done

int ecall_online_u_get_ctres_pres_sres(uint8_t *ctres_data, uint64_t *pres_data, uint64_t *sres_data); //Done

static int
online_u_get_ctres_pres_sres(struct common_context *common, struct online_u_context *online_u, uint8_t *ctres_data,
                             uint64_t *pres_data, uint64_t *sres_data); //Done

/*
 * Online operations for CA
 */
int ecall_online_ca_initialise(const uint8_t *d_data_sealed, size_t d_data_sealed_size); //Done

static int
online_ca_initialise(struct common_context *common, struct online_ca_context *online_ca, const uint8_t *d_data_sealed,
                     size_t d_data_sealed_size); //Done

int ecall_online_ca_set_ctres_pres_sres_and_compute_res(const uint8_t *ctres_data, const uint64_t *pres_data,
                                                        const uint64_t *sres_data); //Done

static int online_ca_set_ctres_pres_sres_and_compute_res(struct common_context *common,
                                                         struct online_ca_context *online_ca, const uint8_t *ctres_data,
                                                         const uint64_t *pres_data, const uint64_t *sres_data); //Done

int ecall_online_ca_get_res(uint8_t *res_data); //Done

static int
online_ca_get_res(struct common_context *common, struct online_ca_context *online_ca, uint8_t *res_data); //Done

/*
 *
 *
 *
 *
 *
 *
 *
 *
 */

/*
 * Create a BigNum state ideal for EC_ORDER_BIT_SIZE bits
 */
static IppsBigNumState *bn_create_state(struct common_context *common) {
    IppsBigNumState *n = (IppsBigNumState *) malloc(common->bn_context_size);
    if (n == NULL) {
        return NULL;
    }

    int ipp_status = ippsBigNumInit(common->ec_order_u32_size, n);
    if (ipp_status != ippStsNoErr) {
        free(n);

        return NULL;
    }

    return n;
}

/*
 * Create a BigNum state ideal for 2 * EC_ORDER_BIT_SIZE bits
 */
static IppsBigNumState *bn_create_state_double_size(struct common_context *common) {
    IppsBigNumState *n = (IppsBigNumState *) malloc((common->bn_context_size) * 2);
    if (n == NULL) {
        return NULL;
    }

    int ipp_status = ippsBigNumInit((common->ec_order_u32_size) * 2, n);
    if (ipp_status != ippStsNoErr) {
        free(n);

        return NULL;
    }

    return n;
}

/*
 * Set BigNum value from uint32_t array
 */
static int bn_set_value(struct common_context *common, IppsBigNumState *number, int u32_size, const uint32_t *value) {
    if (common == NULL || number == NULL || u32_size < 1 || u32_size > common->ec_order_u32_size) {
        return -1;
    }

    int ipp_status = ippsSet_BN(IppsBigNumPOS, u32_size, value, number);
    if (ipp_status != ippStsNoErr) {
        return -1;
    }

    return 0;
}

/*
 * Set BigNum value from a uint32_t value
 */
static int bn_set_value_u32(struct common_context *common, IppsBigNumState *number, uint32_t value) {
    return bn_set_value(common, number, 1, (const uint32_t *) &value);
}

/*
 * Set BigNum value from a uint64_t value
 */
static int bn_set_value_u64(struct common_context *common, IppsBigNumState *number, uint64_t value) {
    return bn_set_value(common, number, 2, (const uint32_t *) &value);
}

/*
 * Set BigNum value to random
 */
static int bn_set_value_random(struct common_context *common, IppsBigNumState *number) {
    // generate random value
    Ipp32u rand_value[common->ec_order_u32_size];
    sgx_status_t sgx_ret = sgx_read_rand((unsigned char *) &rand_value, common->ec_order_size);
    if (sgx_ret != SGX_SUCCESS) {
        return -1;
    }

    // set random value
    if (bn_set_value(common, number, common->ec_order_u32_size, (const uint32_t *) rand_value) < 0) {
        return -1;
    }

    int ipp_status = ippsMod_BN(number, common->q, number);
    if (ipp_status != ippStsNoErr) {
        return -1;
    }

    return 0;
}

/*
 * Create a Point state
 */
static IppsECCPPointState *point_create_state(struct common_context *common) {
    // allocate memory for point context
    IppsECCPPointState *P = (IppsECCPPointState *) malloc(common->point_context_size);
    if (P == NULL) {
        return NULL;
    }

    // initialise point context
    int ipp_status = ippsECCPPointInit(common->ec_order_bit_size, P);
    if (ipp_status != ippStsNoErr) {
        free(P);

        return NULL;
    }

    return P;
}

/*
 * Compute -scalar * point
 */
static int
point_mul_scalar_neg(struct common_context *common, const IppsECCPPointState *point, const IppsBigNumState *scalar,
                     IppsECCPPointState *result) {
    // multiply
    int ipp_status = ippsECCPMulPointScalar(point, scalar, result, common->E);
    if (ipp_status != ippStsNoErr) {
        return -1;
    }

    // negate
    ipp_status = ippsECCPNegativePoint(result, result, common->E);
    if (ipp_status != ippStsNoErr) {
        return -1;
    }

    return 0;

}

int ecall_common_initialise(uint32_t n) {
    return common_initialise(&context_common, n);
}

static int common_initialise(struct common_context *common, uint32_t n) {
    if (n < 1) {
        return -1;
    }
    common->n = n;

    // get EC context size in bytes
    int ec_context_size = 0;
    int ipp_status = ippsECCPGetSizeStd256r1(&ec_context_size);
    if (ipp_status != ippStsNoErr) {
        return -1;
    }
    common->ec_context_size = ec_context_size;

    // allocate memory for EC context
    IppsECCPState *E = (IppsECCPState *) malloc(ec_context_size);
    if (E == NULL) {
        return -1;
    }
    common->E = E;

    // initialise EC context
    ipp_status = ippsECCPInitStd256r1(E);
    if (ipp_status != ippStsNoErr) {
        free(E);

        return -1;
    }

    // set EC context
    ipp_status = ippsECCPSetStd256r1(E);
    if (ipp_status != ippStsNoErr) {
        free(E);

        return -1;
    }

    // get EC order bit size
    int ec_order_bit_size = 0;
    ipp_status = ippsECCPGetOrderBitSize(&ec_order_bit_size, E);
    if (ipp_status != ippStsNoErr) {
        free(E);

        return -1;
    }

    // EC order bit size must be EC_ORDER_BIT_SIZE
    if (ec_order_bit_size != EC_ORDER_BIT_SIZE) {
        free(E);

        return -1;
    }

    common->ec_order_bit_size = ec_order_bit_size;

    // get EC order byte size
    int ec_order_size = 1 + ((ec_order_bit_size - 1) / 8);
    common->ec_order_size = ec_order_size;

    // get EC order size in number of 32-bit integers
    int ec_order_u32_size = 1 + ((ec_order_bit_size - 1) / 32);
    common->ec_order_u32_size = ec_order_u32_size;

    // get IppsBigNumState context size in bytes
    int bn_context_size = 0;
    ipp_status = ippsBigNumGetSize(ec_order_u32_size, &bn_context_size);
    if (ipp_status != ippStsNoErr) {
        free(E);

        return -1;
    }
    common->bn_context_size = bn_context_size;

    // allocate memory for temporary number
    IppsBigNumState *tmp = bn_create_state(&context_common);
    if (tmp == NULL) {
        free(E);

        return -1;
    }

    // allocate memory for q
    IppsBigNumState *q = bn_create_state(&context_common);
    if (q == NULL) {
        free(E);
        free(tmp);

        return -1;
    }
    common->q = q;

    // allocate memory for gx
    IppsBigNumState *gx = bn_create_state(&context_common);
    if (gx == NULL) {
        free(E);
        free(tmp);
        free(q);

        return -1;
    }

    // allocate memory for gy
    IppsBigNumState *gy = bn_create_state(&context_common);
    if (gy == NULL) {
        free(E);
        free(tmp);
        free(q);
        free(gx);

        return -1;
    }

    // get q, gx, gy
    int co_factor = 0;
    ipp_status = ippsECCPGet(tmp, tmp, tmp, gx, gy, q, &co_factor, E);
    if (ipp_status != ippStsNoErr) {
        free(E);
        free(tmp);
        free(q);
        free(gx);
        free(gy);

        return -1;
    }

    // get G

    // get IppsECCPPoint context size in bytes
    int point_context_size;
    ipp_status = ippsECCPPointGetSize(ec_order_bit_size, &point_context_size);
    if (ipp_status != ippStsNoErr) {
        free(E);
        free(tmp);
        free(q);
        free(gx);
        free(gy);

        return -1;
    }
    common->point_context_size = point_context_size;

    // allocate memory for point context
    IppsECCPPointState *G = point_create_state(common);
    if (G == NULL) {
        free(E);
        free(tmp);
        free(q);
        free(gx);
        free(gy);

        return -1;
    }
    common->G = G;

    // set point context
    ipp_status = ippsECCPSetPoint(gx, gy, G, E);
    if (ipp_status != ippStsNoErr) {
        free(E);
        free(tmp);
        free(q);
        free(gx);
        free(gy);
        free(G);

        return -1;
    }

    // free temporary number
    free(tmp);

    // free gx and gy
    free(gx);
    free(gy);

    return 0;
}

int ecall_decode_result(const uint8_t *result_data, uint64_t *decoded_result) {
    return decode_result(&context_common, result_data, decoded_result);
}

static int decode_result(struct common_context *common, const uint8_t *result_data, uint64_t *decoded_result) {
    // allocate memory for result point
    IppsECCPPointState *Result = point_create_state(common);
    if (Result == NULL) {
        return -1;
    }

    {
        // Set Result point coordinates from result_data
        IppsBigNumState *x = bn_create_state(common);
        if (x == NULL) {
            free(Result);

            return -1;
        }

        IppsBigNumState *y = bn_create_state(common);
        if (y == NULL) {
            free(Result);
            free(x);

            return -1;
        }

        int ret = bn_set_value(common, x, common->ec_order_u32_size, (const uint32_t *) (result_data));
        if (ret < 0) {
            free(Result);
            free(x);
            free(y);

            return -1;
        }

        ret = bn_set_value(common, y, common->ec_order_u32_size,
                           (const uint32_t *) (result_data + common->ec_order_size));
        if (ret < 0) {
            free(Result);
            free(x);
            free(y);

            return -1;
        }

        int ipp_status = ippsECCPSetPoint(x, y, Result, common->E);
        if (ipp_status != ippStsNoErr) {
            free(Result);
            free(x);
            free(y);

            return -1;
        }

        free(x);
        free(y);
    }

    // allocate memory for temporary point
    IppsECCPPointState *P = point_create_state(common);
    if (P == NULL) {
        free(Result);

        return -1;
    }

    // allocate memory for result scalar
    IppsBigNumState *result = bn_create_state(common);
    if (result == NULL) {
        free(Result);
        free(P);

        return -1;
    }

    // search for result
    int failed = 0;
    for (uint64_t i = 0; i <= UINT64_MAX; i++) {
        // result = i
        int ret = bn_set_value_u64(common, result, i);
        if (ret < 0) {
            failed = 1;
            break;
        }

        // P = i * G
        int ipp_status = ippsECCPMulPointScalar(common->G, result, P, common->E);
        if (ipp_status != ippStsNoErr) {
            failed = 1;
            break;
        }

        // check if P equals Result
        IppECResult res;
        ipp_status = ippsECCPComparePoint(P, Result, &res, common->E);
        if (ipp_status != ippStsNoErr) {
            failed = 1;
            break;
        }

        // result found
        if (res == ippECPointIsEqual) {
            *decoded_result = i;
            break;
        }
    }

    free(Result);
    free(P);
    free(result);

    if (failed) {
        return -1;
    }

    return 0;
}

int ecall_offline_t_initialise() {
    return offline_t_initialise(&context_common, &context_offline_t);
}

static int offline_t_initialise(struct common_context *common, struct offline_t_context *offline_t) {
    // allocate memory for x
    IppsBigNumState *x = bn_create_state(common);
    if (x == NULL) {
        return -1;
    }
    offline_t->x = x;

    // choose random value for x
    int ret = bn_set_value_random(common, x);
    if (ret < 0) {
        free(x);

        return -1;
    }

    return 0;
}

int ecall_offline_t_set_Ws_and_compute_cts(const uint8_t *Ws_data, size_t Ws_data_size) {
    return offline_t_set_Ws_and_compute_cts(&context_common, &context_offline_t, Ws_data, Ws_data_size);
}

static int offline_t_set_Ws_and_compute_cts(struct common_context *common, struct offline_t_context *offline_t,
                                            const uint8_t *Ws_data, const size_t Ws_data_size) {
    if (Ws_data == NULL || Ws_data_size < common->n * common->ec_order_size * 2) {
        return -1;
    }

    IppsECCPPointState **Ws = (IppsECCPPointState **) calloc(common->n, sizeof(IppsECCPPointState * ));
    if (Ws == NULL) {
        return -1;
    }
    offline_t->Ws = Ws;

    IppsECCPPointState **cts = (IppsECCPPointState **) calloc(2 * common->n, sizeof(IppsECCPPointState * ));
    if (cts == NULL) {
        free(Ws);

        return -1;
    }
    offline_t->cts = cts;

    int ipp_status = 0;

    IppsBigNumState *x = bn_create_state(common);
    if (x == NULL) {
        free(Ws);
        free(cts);

        return -1;
    }
    IppsBigNumState *y = bn_create_state(common);
    if (y == NULL) {
        free(Ws);
        free(cts);
        free(x);

        return -1;
    }

    int p_buffer_len = common->ec_order_u32_size;
    uint32_t p_buffer[p_buffer_len];

    IppsBigNumState *k = bn_create_state(common);
    if (k == NULL) {
        free(Ws);
        free(cts);
        free(x);
        free(y);

        return -1;
    }

    int failed = 0;
    for (uint32_t i = 0; i < common->n; i++) {
        // get W
        size_t offset_x = i * common->ec_order_size * 2;
        memcpy(p_buffer, Ws_data + offset_x, common->ec_order_size);
        int ret = bn_set_value(common, x, p_buffer_len, p_buffer);
        if (ret < 0) {
            failed = 1;
            break;
        }

        size_t offset_y = offset_x + common->ec_order_size;
        memcpy(p_buffer, Ws_data + offset_y, common->ec_order_size);
        ret = bn_set_value(common, y, p_buffer_len, p_buffer);
        if (ret < 0) {
            failed = 1;
            break;
        }

        IppsECCPPointState *W = point_create_state(common);
        if (W == NULL) {
            failed = 1;
            break;
        }
        Ws[i] = W;

        ipp_status = ippsECCPSetPoint(x, y, W, common->E);
        if (ipp_status != ippStsNoErr) {
            failed = 1;
            break;
        }

        // generate k
        ret = bn_set_value_random(common, k);
        if (ret < 0) {
            failed = 1;
            break;
        }

        // compute Gk
        IppsECCPPointState *Gk = point_create_state(common);
        if (Gk == NULL) {
            failed = 1;
            break;
        }
        cts[i * 2] = Gk;

        ipp_status = ippsECCPMulPointScalar(common->G, k, Gk, common->E);
        if (ipp_status != ippStsNoErr) {
            failed = 1;
            break;
        }

        // compute Gxk
        IppsECCPPointState *GxkW = point_create_state(common);
        if (GxkW == NULL) {
            failed = 1;
            break;
        }
        cts[i * 2 + 1] = GxkW;

        ipp_status = ippsECCPMulPointScalar(Gk, offline_t->x, GxkW, common->E);
        if (ipp_status != ippStsNoErr) {
            failed = 1;
            break;
        }

        // compute Gxk * W
        ipp_status = ippsECCPAddPoint(GxkW, W, GxkW, common->E);
        if (ipp_status != ippStsNoErr) {
            failed = 1;
            break;
        }

    }

    if (failed) {
        // error, free everything
        for (uint32_t i = 0; i < common->n; i++) {
            free(Ws[i]);
        }

        for (uint32_t i = 0; i < 2 * common->n; i++) {
            free(cts[i]);
        }

        free(Ws);
        free(cts);
        free(x);
        free(y);
        free(k);

        return -1;
    }

    free(x);
    free(y);
    free(k);

    return 0;
}

int ecall_offline_t_get_x_and_cts(uint8_t *x_data_sealed, size_t *x_data_sealed_size, uint8_t *cts_data_sealed,
                                  size_t *cts_data_sealed_size) {
    return offline_t_get_x_and_cts(&context_common, &context_offline_t, x_data_sealed, x_data_sealed_size,
                                   cts_data_sealed, cts_data_sealed_size);
}

static int
offline_t_get_x_and_cts(struct common_context *common, struct offline_t_context *offline_t, uint8_t *x_data_sealed,
                        size_t *x_data_sealed_size,
                        uint8_t *cts_data_sealed, size_t *cts_data_sealed_size) {
    // buffer for unsealed data
    uint8_t *x_data = NULL;
    uint32_t x_data_size = common->ec_order_size;
    uint8_t *cts_data = NULL;
    uint32_t cts_data_size = common->n * common->ec_order_size * 4;

    // calculate sealed data size
    uint32_t x_sealed_size = sgx_calc_sealed_data_size(0, x_data_size);
    uint32_t cts_sealed_size = sgx_calc_sealed_data_size(0, cts_data_size);

    // check if buffer sufficiently large
    if (*x_data_sealed_size < x_sealed_size || *cts_data_sealed_size < cts_sealed_size) {
        return -1;
    }

    x_data = (uint8_t *) malloc(x_data_size);
    cts_data = (uint8_t *) malloc(cts_data_size);
    if (x_data == NULL || cts_data == NULL) {
        free(x_data);
        free(cts_data);

        return -1;
    }

    int ipp_status = 0;
    sgx_status_t sgx_ret;

    // extract value of x
    IppsBigNumSGN sign;
    int x_buffer_len = common->ec_order_u32_size;

    ipp_status = ippsGet_BN(&sign, &x_buffer_len, (Ipp32u *) x_data, offline_t->x);
    if (sign == IppsBigNumNEG || ipp_status != ippStsNoErr) {
        free(x_data);
        free(cts_data);

        return -1;
    }

    // seal x
    sgx_ret = sgx_seal_data(0, NULL, x_data_size, x_data, x_sealed_size, (sgx_sealed_data_t *) x_data_sealed);
    if (sgx_ret != SGX_SUCCESS) {
        free(x_data);
        free(cts_data);

        return -1;
    }
    *x_data_sealed_size = x_sealed_size;

    // extract values of cts
    IppsBigNumState *x = bn_create_state(common);
    if (x == NULL) {
        free(x_data);
        free(cts_data);

        return -1;
    }
    IppsBigNumState *y = bn_create_state(common);
    if (y == NULL) {
        free(x_data);
        free(cts_data);
        free(x);

        return -1;
    }

    for (uint32_t i = 0; i < common->n * 2; i++) {
        // get x and y coordinates from point
        ipp_status = ippsECCPGetPoint(x, y, offline_t->cts[i], common->E);

        if (ipp_status != ippStsNoErr) {
            free(x_data);
            free(cts_data);
            free(x);
            free(y);

            return -1;
        }

        IppsBigNumSGN sign;
        int p_buffer_len = common->ec_order_u32_size;
        uint32_t p_buffer[p_buffer_len];

        // extract x-coordinate
        ipp_status = ippsGet_BN(&sign, &p_buffer_len, p_buffer, x);
        if (sign == IppsBigNumNEG || ipp_status != ippStsNoErr) {
            free(x_data);
            free(cts_data);
            free(x);
            free(y);

            return -1;
        }

        size_t offset_x = i * common->ec_order_size * 2;
        memcpy(cts_data + offset_x, p_buffer, common->ec_order_size);

        // extract y-coordinate
        ipp_status = ippsGet_BN(&sign, &p_buffer_len, p_buffer, y);
        if (sign == IppsBigNumNEG || ipp_status != ippStsNoErr) {
            free(x_data);
            free(cts_data);
            free(x);
            free(y);

            return -1;
        }

        size_t offset_y = offset_x + common->ec_order_size;
        memcpy(cts_data + offset_y, p_buffer, common->ec_order_size);
    }

    // seal cts
    sgx_ret = sgx_seal_data(0, NULL, cts_data_size, cts_data, cts_sealed_size, (sgx_sealed_data_t *) cts_data_sealed);
    if (sgx_ret != SGX_SUCCESS) {
        free(x_data);
        free(cts_data);
        free(x);
        free(y);

        return -1;
    }
    *cts_data_sealed_size = cts_sealed_size;

    free(x_data);
    free(cts_data);
    free(x);
    free(y);

    return 0;
}

int ecall_offline_ca_initialise() {
    return offline_ca_initialise(&context_common, &context_offline_ca);
}

static int offline_ca_initialise(struct common_context *common, struct offline_ca_context *offline_ca) {
    // allocate memory for d
    IppsBigNumState *d = bn_create_state(common);
    if (d == NULL) {
        return -1;
    }
    context_offline_ca.d = d;

    // choose random value for d
    int ret = bn_set_value_random(common, d);
    if (ret < 0) {
        free(d);

        return -1;
    }

    // allocate memory for e
    IppsBigNumState *e = bn_create_state(common);
    if (e == NULL) {
        free(d);

        return -1;
    }
    context_offline_ca.e = e;

    // compute inverse of d
    int ipp_status = ippsModInv_BN(d, common->q, e);
    if (ipp_status != ippStsNoErr) {
        free(d);
        free(e);

        return -1;
    }

    return 0;
}

int ecall_offline_ca_set_ws_and_compute_Ws(uint32_t *ws) {
    if (ws == NULL) {
        return -1;
    }

    return offline_ca_set_ws_and_compute_Ws(&context_common, &context_offline_ca, ws);
}

static int
offline_ca_set_ws_and_compute_Ws(struct common_context *common, struct offline_ca_context *offline_ca, uint32_t *ws) {
    // allocate memory for array of pointers to points
    IppsECCPPointState **Ws = (IppsECCPPointState **) calloc(common->n, sizeof(IppsECCPPointState * ));
    if (Ws == NULL) {
        return -1;
    }
    offline_ca->Ws = Ws;

    IppsBigNumState *bn_i_plus_w_plus_one = bn_create_state(common);
    if (bn_i_plus_w_plus_one == NULL) {
        free(Ws);

        return -1;
    }

    int failed = 0;
    for (uint32_t i = 1; i <= common->n; i++) {
        // allocate memory for Wi
        IppsECCPPointState *W = point_create_state(common);
        if (W == NULL) {
            failed = 1;
            break;
        }

        uint32_t i_plus_w_plus_one = i + ws[i - 1] + 1;
        int ret = bn_set_value_u32(common, bn_i_plus_w_plus_one, i_plus_w_plus_one);
        if (ret < 0) {
            failed = 1;
            break;
        }

        int ipp_status = ippsECCPMulPointScalar(common->G, offline_ca->e, W, common->E);
        if (ipp_status != ippStsNoErr) {
            failed = 1;
            break;
        }

        ipp_status = ippsECCPMulPointScalar(W, bn_i_plus_w_plus_one, W, common->E);
        if (ipp_status != ippStsNoErr) {
            failed = 1;
            break;
        }

        Ws[i - 1] = W;
    }

    if (failed) {
        // error, free everything
        for (uint32_t i = 0; i < common->n; i++) {
            free(Ws[i]);
        }

        free(Ws);
        free(bn_i_plus_w_plus_one);

        return -1;
    }

    free(bn_i_plus_w_plus_one);

    return 0;
}

int ecall_offline_ca_get_d_and_Ws(uint8_t *d_data_sealed, size_t *d_data_sealed_size, uint8_t *Ws_data,
                                  size_t Ws_data_size) {
    return offline_ca_get_d_and_Ws(&context_common, &context_offline_ca, d_data_sealed, d_data_sealed_size, Ws_data,
                                   Ws_data_size);
}

static int
offline_ca_get_d_and_Ws(struct common_context *common, struct offline_ca_context *offline_ca, uint8_t *d_data_sealed,
                        size_t *d_data_sealed_size,
                        uint8_t *Ws_data, size_t Ws_data_size) {
    // buffer for unsealed data
    uint8_t *d_data = NULL;
    uint32_t d_data_size = common->ec_order_size;

    // calculate sealed data size
    uint32_t d_sealed_size = sgx_calc_sealed_data_size(0, d_data_size);

    // check if buffer sufficiently large
    if (*d_data_sealed_size < d_sealed_size) {
        return -1;
    }
    if (Ws_data != NULL && Ws_data_size < common->n * common->ec_order_size * 2) {
        return -1;
    }

    d_data = (uint8_t *) malloc(d_data_size);
    if (d_data == NULL) {
        free(d_data);

        return -1;
    }

    int ipp_status = 0;
    sgx_status_t sgx_ret;

    // extract value of d
    IppsBigNumSGN sign;
    int d_buffer_len = common->ec_order_u32_size;

    ipp_status = ippsGet_BN(&sign, &d_buffer_len, (Ipp32u *) d_data, offline_ca->d);
    if (sign == IppsBigNumNEG || ipp_status != ippStsNoErr) {
        free(d_data);

        return -1;
    }

    // seal d
    sgx_ret = sgx_seal_data(0, NULL, d_data_size, d_data, d_sealed_size, (sgx_sealed_data_t *) d_data_sealed);
    if (sgx_ret != SGX_SUCCESS) {
        free(d_data);

        return -1;
    }
    *d_data_sealed_size = d_sealed_size;

    // extract values of Ws
    IppsBigNumState *x = bn_create_state(common);
    if (x == NULL) {
        free(d_data);

        return -1;
    }
    IppsBigNumState *y = bn_create_state(common);
    if (y == NULL) {
        free(d_data);
        free(x);

        return -1;
    }

    for (uint32_t i = 0; i < common->n; i++) {
        // get x and y coordinates from point
        ipp_status = ippsECCPGetPoint(x, y, offline_ca->Ws[i], common->E);

        if (ipp_status != ippStsNoErr) {
            free(d_data);
            free(x);
            free(y);

            return -1;
        }

        IppsBigNumSGN sign;
        int p_buffer_len = common->ec_order_u32_size;
        uint32_t p_buffer[p_buffer_len];

        // extract x-coordinate
        ipp_status = ippsGet_BN(&sign, &p_buffer_len, p_buffer, x);
        if (sign == IppsBigNumNEG || ipp_status != ippStsNoErr) {
            free(d_data);
            free(x);
            free(y);

            return -1;
        }

        size_t offset_x = i * common->ec_order_size * 2;
        memcpy(Ws_data + offset_x, p_buffer, common->ec_order_size);

        // extract y-coordinate
        ipp_status = ippsGet_BN(&sign, &p_buffer_len, p_buffer, y);
        if (sign == IppsBigNumNEG || ipp_status != ippStsNoErr) {
            free(d_data);
            free(x);
            free(y);

            return -1;
        }

        size_t offset_y = offset_x + common->ec_order_size;
        memcpy(Ws_data + offset_y, p_buffer, common->ec_order_size);
    }

    free(d_data);
    free(x);
    free(y);

    return 0;
}

int ecall_online_t_initialise(const uint8_t *x_data_sealed, size_t x_data_sealed_size) {
    return online_t_initialise(&context_common, &context_online_t, x_data_sealed, x_data_sealed_size);
}

static int
online_t_initialise(struct common_context *common, struct online_t_context *online_t, const uint8_t *x_data_sealed,
                    size_t x_data_sealed_size) {
    // buffer for unsealed data
    uint8_t *x_data = (uint8_t *) malloc(common->ec_order_size);
    uint32_t x_data_size = common->ec_order_size;
    if (x_data == NULL) {
        return -1;
    }

    sgx_status_t sgx_ret;

    // unseal x
    sgx_ret = sgx_unseal_data((sgx_sealed_data_t *) x_data_sealed, NULL, NULL, x_data, &x_data_size);
    if (sgx_ret != SGX_SUCCESS || x_data_size != common->ec_order_size) {
        free(x_data);

        return -1;
    }

    IppsBigNumState *x = bn_create_state(common);
    if (x == NULL) {
        free(x_data);

        return -1;
    }

    int ret = bn_set_value(common, x, common->ec_order_u32_size, (const uint32_t *) x_data);
    if (ret < 0) {
        free(x_data);
        free(x);

        return -1;
    }

    online_t->x = x;

    free(x_data);

    return 0;
}

int ecall_online_t_unseal_cts(const uint8_t *cts_data_sealed, size_t cts_data_sealed_size, uint8_t *cts_data,
                              size_t cts_data_size) {
    return online_t_unseal_cts(&context_common, &context_online_t, cts_data_sealed, cts_data_sealed_size, cts_data,
                               cts_data_size);
}

static int
online_t_unseal_cts(struct common_context *common, struct online_t_context *online_t, const uint8_t *cts_data_sealed,
                    size_t cts_data_sealed_size, uint8_t *cts_data,
                    size_t cts_data_size) {
    // unseal cts
    sgx_status_t sgx_ret = sgx_unseal_data((sgx_sealed_data_t *) cts_data_sealed, NULL, NULL, cts_data,
                                           (uint32_t * ) & cts_data_size);
    if (sgx_ret != SGX_SUCCESS || cts_data_size != common->n * common->ec_order_size * 4) {
        return -1;
    }

    return 0;
}

int ecall_online_t_set_res_and_get_result(const uint8_t *res_data, uint8_t *result_data) {
    return online_t_set_res_and_get_result(&context_common, &context_online_t, res_data, result_data);
}

static int online_t_set_res_and_get_result(struct common_context *common, struct online_t_context *online_t,
                                           const uint8_t *res_data, uint8_t *result_data) {
    IppsBigNumState *ax = bn_create_state(common);
    if (ax == NULL) {
        return -1;
    }

    IppsBigNumState *ay = bn_create_state(common);
    if (ay == NULL) {
        free(ax);

        return -1;
    }

    IppsBigNumState *bx = bn_create_state(common);
    if (bx == NULL) {
        free(ax);
        free(ay);

        return -1;
    }

    IppsBigNumState *by = bn_create_state(common);
    if (by == NULL) {
        free(ax);
        free(ay);
        free(bx);

        return -1;
    }

    // set x and y coordinates
    int ret = bn_set_value(common, ax, common->ec_order_u32_size, (const uint32_t *) (res_data));
    ret += bn_set_value(common, ay, common->ec_order_u32_size, (const uint32_t *) (res_data + common->ec_order_size));
    ret += bn_set_value(common, bx, common->ec_order_u32_size,
                        (const uint32_t *) (res_data + (common->ec_order_size * 2)));
    ret += bn_set_value(common, by, common->ec_order_u32_size,
                        (const uint32_t *) (res_data + (common->ec_order_size * 3)));
    if (ret != 0) {
        free(ax);
        free(ay);
        free(bx);
        free(by);

        return -1;
    }

    // create point A and B from x and y coordinates
    IppsECCPPointState *A = point_create_state(common);
    if (A == NULL) {
        free(ax);
        free(ay);
        free(bx);
        free(by);

        return -1;
    }

    int ipp_status = ippsECCPSetPoint(ax, ay, A, common->E);
    if (ipp_status != ippStsNoErr) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);

        return -1;
    }

    IppsECCPPointState *B = point_create_state(common);
    if (B == NULL) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);

        return -1;
    }

    ipp_status = ippsECCPSetPoint(bx, by, B, common->E);
    if (ipp_status != ippStsNoErr) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);

        return -1;
    }

    // result point
    IppsECCPPointState *Result = point_create_state(common);
    if (Result == NULL) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);

        return -1;
    }

    // -x * A
    ret = point_mul_scalar_neg(common, A, online_t->x, Result);
    if (ret < 0) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);
        free(Result);

        return -1;
    }

    // B + (-x * A)
    ipp_status = ippsECCPAddPoint(B, Result, Result, common->E);
    if (ipp_status != ippStsNoErr) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);
        free(Result);

        return -1;
    }

    // x and y coordinates for Result
    IppsBigNumState *x = bn_create_state(common);
    if (x == NULL) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);
        free(Result);

        return -1;
    }

    IppsBigNumState *y = bn_create_state(common);
    if (y == NULL) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);
        free(Result);
        free(x);

        return -1;
    }

    // get x and y coordinates from Result
    ipp_status = ippsECCPGetPoint(x, y, Result, common->E);
    if (ipp_status != ippStsNoErr) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);
        free(Result);
        free(x);
        free(y);

        return -1;
    }

    IppsBigNumSGN sign;
    int p_buffer_len = common->ec_order_u32_size;
    uint32_t p_buffer[p_buffer_len];

    // extract x-coordinate
    ipp_status = ippsGet_BN(&sign, &p_buffer_len, p_buffer, x);
    if (sign == IppsBigNumNEG || ipp_status != ippStsNoErr) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);
        free(Result);
        free(x);
        free(y);

        return -1;
    }
    memcpy(result_data, p_buffer, common->ec_order_size);

    // extract y-coordinate
    ipp_status = ippsGet_BN(&sign, &p_buffer_len, p_buffer, y);
    if (sign == IppsBigNumNEG || ipp_status != ippStsNoErr) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);
        free(Result);
        free(x);
        free(y);

        return -1;
    }
    memcpy(result_data + common->ec_order_size, p_buffer, common->ec_order_size);

    free(ax);
    free(ay);
    free(bx);
    free(by);
    free(A);
    free(B);
    free(Result);
    free(x);
    free(y);

    return 0;
}

int ecall_online_u_initialise(const uint8_t *snps) {
    return online_u_initialise(&context_common, &context_online_u, snps);
}

static int
online_u_initialise(struct common_context *common, struct online_u_context *online_u, const uint8_t *snps) {
    uint8_t *s = (uint8_t *) malloc(common->n);
    if (s == NULL) {
        return -1;
    }
    online_u->snps = s;

    // copy SNPs
    memcpy(s, snps, common->n);

    return 0;
}

int ecall_online_u_set_cts_and_compute_ctres_pres_sres(const uint8_t *cts_data, size_t cts_data_size) {
    return online_u_set_cts_and_compute_ctres_pres_sres(&context_common, &context_online_u, cts_data, cts_data_size);
}

static int
online_u_set_cts_and_compute_ctres_pres_sres(struct common_context *common, struct online_u_context *online_u,
                                             const uint8_t *cts_data, size_t cts_data_size) {
    if (cts_data == NULL || cts_data_size < common->n * common->ec_order_size * 4) {
        return -1;
    }

    // ctres A
    IppsECCPPointState *A = point_create_state(common);
    if (A == NULL) {
        return -1;
    }
    online_u->ctres[0] = A;

    int ipp_status = ippsECCPSetPointAtInfinity(A, common->E);
    if (ipp_status != ippStsNoErr) {
        free(A);

        return -1;
    }

    // ctres B
    IppsECCPPointState *B = point_create_state(common);
    if (B == NULL) {
        free(A);

        return -1;
    }
    online_u->ctres[1] = B;

    ipp_status = ippsECCPSetPointAtInfinity(B, common->E);
    if (ipp_status != ippStsNoErr) {
        free(A);
        free(B);

        return -1;
    }

    // ct A
    IppsECCPPointState *cta = point_create_state(common);
    if (cta == NULL) {
        free(A);
        free(B);

        return -1;
    }

    // ct A x
    IppsBigNumState *ctax = bn_create_state(common);
    if (ctax == NULL) {
        free(A);
        free(B);
        free(cta);

        return -1;
    }

    // ct A y
    IppsBigNumState *ctay = bn_create_state(common);
    if (ctay == NULL) {
        free(A);
        free(B);
        free(cta);
        free(ctax);

        return -1;
    }

    // ct B
    IppsECCPPointState *ctb = point_create_state(common);
    if (ctb == NULL) {
        free(A);
        free(B);
        free(cta);
        free(ctax);
        free(ctay);

        return -1;
    }

    // ct B x
    IppsBigNumState *ctbx = bn_create_state(common);
    if (ctbx == NULL) {
        free(A);
        free(B);
        free(cta);
        free(ctax);
        free(ctay);
        free(ctb);

        return -1;
    }

    // ct B y
    IppsBigNumState *ctby = bn_create_state(common);
    if (ctby == NULL) {
        free(A);
        free(B);
        free(cta);
        free(ctax);
        free(ctay);
        free(ctb);
        free(ctbx);

        return -1;
    }

    // pres
    online_u->pres = 0;

    // sres
    online_u->sres = 0;

    int failed = 0;
    for (uint32_t i = 0; i < common->n; i++) {
        uint32_t index = i + 1;
        uint8_t snp = online_u->snps[i];

        if (snp == 0) {
            // no changes to ctres
        } else if (snp >= 1) {
            size_t ctax_offset = i * common->ec_order_size * 4;
            size_t ctay_offset = ctax_offset + common->ec_order_size;
            size_t ctbx_offset = ctay_offset + common->ec_order_size;
            size_t ctby_offset = ctbx_offset + common->ec_order_size;

            int ret = 0;
            ret += bn_set_value(common, ctax, common->ec_order_u32_size, (const uint32_t *) (cts_data + ctax_offset));
            ret += bn_set_value(common, ctay, common->ec_order_u32_size, (const uint32_t *) (cts_data + ctay_offset));
            ret += bn_set_value(common, ctbx, common->ec_order_u32_size, (const uint32_t *) (cts_data + ctbx_offset));
            ret += bn_set_value(common, ctby, common->ec_order_u32_size, (const uint32_t *) (cts_data + ctby_offset));
            if (ret != 0) {
                failed = 1;
                break;
            }

            int ipp_status = ippsECCPSetPoint(ctax, ctay, cta, common->E);
            if (ipp_status != ippStsNoErr) {
                failed = 1;
                break;
            }

            ipp_status = ippsECCPSetPoint(ctbx, ctby, ctb, common->E);
            if (ipp_status != ippStsNoErr) {
                failed = 1;
                break;
            }

            if (snp == 1) {
                online_u->pres += index * snp;
                online_u->sres += snp;

                // add ct once
                ipp_status = ippsECCPAddPoint(A, cta, A, common->E);
                if (ipp_status != ippStsNoErr) {
                    failed = 1;
                    break;
                }
                ipp_status = ippsECCPAddPoint(B, ctb, B, common->E);
                if (ipp_status != ippStsNoErr) {
                    failed = 1;
                    break;
                }
            } else if (snp > 1) {
                online_u->pres += index * 2;
                online_u->sres += 2;

                // add ct twice
                ipp_status = ippsECCPAddPoint(A, cta, A, common->E);
                if (ipp_status != ippStsNoErr) {
                    failed = 1;
                    break;
                }
                ipp_status = ippsECCPAddPoint(B, ctb, B, common->E);
                if (ipp_status != ippStsNoErr) {
                    failed = 1;
                    break;
                }

                ipp_status = ippsECCPAddPoint(A, cta, A, common->E);
                if (ipp_status != ippStsNoErr) {
                    failed = 1;
                    break;
                }
                ipp_status = ippsECCPAddPoint(B, ctb, B, common->E);
                if (ipp_status != ippStsNoErr) {
                    failed = 1;
                    break;
                }
            }
        }
    }

    free(cta);
    free(ctax);
    free(ctay);
    free(ctb);
    free(ctbx);
    free(ctby);

    if (failed) {
        return -1;
    }

    return 0;
}

int ecall_online_u_get_ctres_pres_sres(uint8_t *ctres_data, uint64_t *pres_data, uint64_t *sres_data) {
    return online_u_get_ctres_pres_sres(&context_common, &context_online_u, ctres_data, pres_data, sres_data);
}

static int
online_u_get_ctres_pres_sres(struct common_context *common, struct online_u_context *online_u, uint8_t *ctres_data,
                             uint64_t *pres_data, uint64_t *sres_data) {
    IppsBigNumState *ax = bn_create_state(common);
    if (ax == NULL) {
        return -1;
    }

    IppsBigNumState *ay = bn_create_state(common);
    if (ay == NULL) {
        free(ax);

        return -1;
    }

    IppsBigNumState *bx = bn_create_state(common);
    if (bx == NULL) {
        free(ax);
        free(ay);

        return -1;
    }

    IppsBigNumState *by = bn_create_state(common);
    if (by == NULL) {
        free(ax);
        free(ay);
        free(bx);

        return -1;
    }

    // get x and y coordinates from ctres point A
    int ipp_status = ippsECCPGetPoint(ax, ay, online_u->ctres[0], common->E);
    if (ipp_status != ippStsNoErr) {
        free(ax);
        free(ay);
        free(bx);
        free(by);

        return -1;
    }

    IppsBigNumSGN sign;
    int p_buffer_len = common->ec_order_u32_size;
    uint32_t p_buffer[p_buffer_len];

    // extract x-coordinate value
    ipp_status = ippsGet_BN(&sign, &p_buffer_len, p_buffer, ax);
    if (sign == IppsBigNumNEG || ipp_status != ippStsNoErr) {
        free(ax);
        free(ay);
        free(bx);
        free(by);

        return -1;
    }
    memcpy(ctres_data, p_buffer, common->ec_order_size);

    // extract y-coordinate value
    ipp_status = ippsGet_BN(&sign, &p_buffer_len, p_buffer, ay);
    if (sign == IppsBigNumNEG || ipp_status != ippStsNoErr) {
        free(ax);
        free(ay);
        free(bx);
        free(by);

        return -1;
    }
    memcpy(ctres_data + common->ec_order_size, p_buffer, common->ec_order_size);

    // get x and y coordinates from ctres point B
    ipp_status = ippsECCPGetPoint(bx, by, online_u->ctres[1], common->E);
    if (ipp_status != ippStsNoErr) {
        free(ax);
        free(ay);
        free(bx);
        free(by);

        return -1;
    }

    // extract x-coordinate value
    ipp_status = ippsGet_BN(&sign, &p_buffer_len, p_buffer, bx);
    if (sign == IppsBigNumNEG || ipp_status != ippStsNoErr) {
        free(ax);
        free(ay);
        free(bx);
        free(by);

        return -1;
    }
    memcpy(ctres_data + (common->ec_order_size) * 2, p_buffer, common->ec_order_size);

    // extract y-coordinate value
    ipp_status = ippsGet_BN(&sign, &p_buffer_len, p_buffer, by);
    if (sign == IppsBigNumNEG || ipp_status != ippStsNoErr) {
        free(ax);
        free(ay);
        free(bx);
        free(by);

        return -1;
    }
    memcpy(ctres_data + (common->ec_order_size) * 3, p_buffer, common->ec_order_size);

    // extract pres value
    memcpy(pres_data, &(online_u->pres), sizeof(uint64_t));

    // extract sres value
    memcpy(sres_data, &(online_u->sres), sizeof(uint64_t));

    free(ax);
    free(ay);
    free(bx);
    free(by);

    return 0;
}

int ecall_online_ca_initialise(const uint8_t *d_data_sealed, size_t d_data_sealed_size) {
    return online_ca_initialise(&context_common, &context_online_ca, d_data_sealed, d_data_sealed_size);
}

static int
online_ca_initialise(struct common_context *common, struct online_ca_context *online_ca, const uint8_t *d_data_sealed,
                     size_t d_data_sealed_size) {
    // buffer for unsealed data
    uint8_t *d_data = (uint8_t *) malloc(common->ec_order_size);
    uint32_t d_data_size = common->ec_order_size;
    if (d_data == NULL) {
        return -1;
    }

    sgx_status_t sgx_ret;

    // unseal d
    sgx_ret = sgx_unseal_data((sgx_sealed_data_t *) d_data_sealed, NULL, NULL, d_data, &d_data_size);
    if (sgx_ret != SGX_SUCCESS || d_data_size != common->ec_order_size) {
        free(d_data);

        return -1;
    }

    IppsBigNumState *d = bn_create_state(common);
    if (d == NULL) {
        free(d_data);

        return -1;
    }
    online_ca->d = d;

    int ret = bn_set_value(common, d, common->ec_order_u32_size, (const uint32_t *) d_data);
    if (ret < 0) {
        free(d_data);
        free(d);

        return -1;
    }

    free(d_data);

    return 0;
}

int ecall_online_ca_set_ctres_pres_sres_and_compute_res(const uint8_t *ctres_data, const uint64_t *pres_data,
                                                        const uint64_t *sres_data) {
    return online_ca_set_ctres_pres_sres_and_compute_res(&context_common, &context_online_ca, ctres_data, pres_data,
                                                         sres_data);
}

static int online_ca_set_ctres_pres_sres_and_compute_res(struct common_context *common,
                                                         struct online_ca_context *online_ca, const uint8_t *ctres_data,
                                                         const uint64_t *pres_data, const uint64_t *sres_data) {
    const uint32_t *ctres_data_u4 = (const uint32_t *) ctres_data;

    IppsBigNumState *ax = bn_create_state(common);
    if (ax == NULL) {
        return -1;
    }

    IppsBigNumState *ay = bn_create_state(common);
    if (ay == NULL) {
        free(ax);

        return -1;
    }

    IppsBigNumState *bx = bn_create_state(common);
    if (bx == NULL) {
        free(ax);
        free(ay);

        return -1;
    }

    IppsBigNumState *by = bn_create_state(common);
    if (by == NULL) {
        free(ax);
        free(ay);
        free(bx);

        return -1;
    }

    // set x and y coordinates
    int ret = bn_set_value(common, ax, common->ec_order_u32_size, ctres_data_u4);
    ret += bn_set_value(common, ay, common->ec_order_u32_size, ctres_data_u4 + common->ec_order_u32_size);
    ret += bn_set_value(common, bx, common->ec_order_u32_size, ctres_data_u4 + common->ec_order_u32_size * 2);
    ret += bn_set_value(common, by, common->ec_order_u32_size, ctres_data_u4 + common->ec_order_u32_size * 3);
    if (ret != 0) {
        free(ax);
        free(ay);
        free(bx);
        free(by);

        return -1;
    }

    // create point A and B from x and y coordinates
    IppsECCPPointState *A = point_create_state(common);
    if (A == NULL) {
        free(ax);
        free(ay);
        free(bx);
        free(by);

        return -1;
    }

    int ipp_status = ippsECCPSetPoint(ax, ay, A, common->E);
    if (ipp_status != ippStsNoErr) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);

        return -1;
    }

    IppsECCPPointState *B = point_create_state(common);
    if (B == NULL) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);

        return -1;
    }

    ipp_status = ippsECCPSetPoint(bx, by, B, common->E);
    if (ipp_status != ippStsNoErr) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);

        return -1;
    }

    // Res point A
    IppsECCPPointState *A_res = point_create_state(common);
    if (A_res == NULL) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);

        return -1;
    }

    ipp_status = ippsECCPMulPointScalar(A, online_ca->d, A_res, common->E);
    if (ipp_status != ippStsNoErr) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);
        free(A_res);

        return -1;
    }

    // Res point B
    IppsECCPPointState *B_res = point_create_state(common);
    if (B_res == NULL) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);
        free(A_res);

        return -1;
    }

    ipp_status = ippsECCPMulPointScalar(B, online_ca->d, B_res, common->E);
    if (ipp_status != ippStsNoErr) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);
        free(A_res);
        free(B_res);

        return -1;
    }

    // -pres * G
    IppsECCPPointState *P_tmp = point_create_state(common);
    if (P_tmp == NULL) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);
        free(A_res);
        free(B_res);

        return -1;
    }

    IppsBigNumState *bn_tmp = bn_create_state(common);
    if (bn_tmp == NULL) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);
        free(A_res);
        free(B_res);
        free(P_tmp);

        return -1;
    }

    ret = bn_set_value_u64(common, bn_tmp, *pres_data);
    if (ret < 0) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);
        free(A_res);
        free(B_res);
        free(P_tmp);
        free(bn_tmp);

        return -1;
    }

    ret = point_mul_scalar_neg(common, common->G, bn_tmp, P_tmp);
    if (ret < 0) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);
        free(A_res);
        free(B_res);
        free(P_tmp);
        free(bn_tmp);

        return -1;
    }

    ipp_status = ippsECCPAddPoint(B_res, P_tmp, B_res, common->E);
    if (ipp_status != ippStsNoErr) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);
        free(A_res);
        free(B_res);
        free(P_tmp);
        free(bn_tmp);

        return -1;
    }

    // -sres * G
    ret = bn_set_value_u64(common, bn_tmp, *sres_data);
    if (ret < 0) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);
        free(A_res);
        free(B_res);
        free(P_tmp);
        free(bn_tmp);

        return -1;
    }

    ret = point_mul_scalar_neg(common, common->G, bn_tmp, P_tmp);
    if (ret < 0) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);
        free(A_res);
        free(B_res);
        free(P_tmp);
        free(bn_tmp);

        return -1;
    }

    ipp_status = ippsECCPAddPoint(B_res, P_tmp, B_res, common->E);
    if (ipp_status != ippStsNoErr) {
        free(ax);
        free(ay);
        free(bx);
        free(by);
        free(A);
        free(B);
        free(A_res);
        free(B_res);
        free(P_tmp);
        free(bn_tmp);

        return -1;
    }

    online_ca->res[0] = A_res;
    online_ca->res[1] = B_res;

    free(ax);
    free(ay);
    free(bx);
    free(by);
    free(A);
    free(B);
    free(P_tmp);
    free(bn_tmp);

    return 0;
}

int ecall_online_ca_get_res(uint8_t *res_data) {
    return online_ca_get_res(&context_common, &context_online_ca, res_data);
}

static int
online_ca_get_res(struct common_context *common, struct online_ca_context *online_ca, uint8_t *res_data) {
    IppsBigNumState *x = bn_create_state(common);
    if (x == NULL) {
        return -1;
    }
    IppsBigNumState *y = bn_create_state(common);
    if (y == NULL) {
        free(x);

        return -1;
    }

    // get x and y coordinates from res point A
    int ipp_status = ippsECCPGetPoint(x, y, online_ca->res[0], common->E);
    if (ipp_status != ippStsNoErr) {
        free(x);
        free(y);

        return -1;
    }

    IppsBigNumSGN sign;
    int p_buffer_len = common->ec_order_u32_size;
    uint32_t p_buffer[p_buffer_len];

    // extract x-coordinate
    ipp_status = ippsGet_BN(&sign, &p_buffer_len, p_buffer, x);
    if (sign == IppsBigNumNEG || ipp_status != ippStsNoErr) {
        free(x);
        free(y);

        return -1;
    }
    memcpy(res_data, p_buffer, common->ec_order_size);

    // extract y-coordinate
    ipp_status = ippsGet_BN(&sign, &p_buffer_len, p_buffer, y);
    if (sign == IppsBigNumNEG || ipp_status != ippStsNoErr) {
        free(x);
        free(y);

        return -1;
    }
    memcpy(res_data + common->ec_order_size, p_buffer, common->ec_order_size);

    // get x and y coordinates from res point B
    ipp_status = ippsECCPGetPoint(x, y, online_ca->res[1], common->E);
    if (ipp_status != ippStsNoErr) {
        free(x);
        free(y);

        return -1;
    }

    // extract x-coordinate
    ipp_status = ippsGet_BN(&sign, &p_buffer_len, p_buffer, x);
    if (sign == IppsBigNumNEG || ipp_status != ippStsNoErr) {
        free(x);
        free(y);

        return -1;
    }
    memcpy(res_data + (common->ec_order_size) * 2, p_buffer, common->ec_order_size);

    // extract y-coordinate
    ipp_status = ippsGet_BN(&sign, &p_buffer_len, p_buffer, y);
    if (sign == IppsBigNumNEG || ipp_status != ippStsNoErr) {
        free(x);
        free(y);

        return -1;
    }
    memcpy(res_data + (common->ec_order_size) * 3, p_buffer, common->ec_order_size);

    free(x);
    free(y);

    return 0;
}

void test_print() {
    ocall_debug_print("test_print called");
}

static int test_printpoint(IppsECCPPointState *P) {
    IppsBigNumState *x = bn_create_state(&context_common);
    if (x == NULL) {
        return -1;
    }
    IppsBigNumState *y = bn_create_state(&context_common);
    if (y == NULL) {
        free(x);

        return -1;
    }

    // get x and y coordinates from point
    int ipp_status = ippsECCPGetPoint(x, y, P, context_common.E);
    if (ipp_status != ippStsNoErr) {
        free(x);
        free(y);

        return -1;
    }

    free(x);
    free(y);

    return 0;
}

static int test_printbn(IppsBigNumState *d) {
    IppsBigNumSGN sign;
    int d_buffer_len = context_common.ec_order_u32_size * 4;
    uint32_t d_buffer[d_buffer_len];

    int ipp_status = ippsGet_BN(&sign, &d_buffer_len, d_buffer, d);
    if (sign == IppsBigNumNEG || ipp_status != ippStsNoErr) {
        ocall_debug_print("ippsGet_BN failed");
        return -1;
    }

    char msg[256] = {0};
    snprintf(msg, sizeof(msg), "buffer size: %lu", d_buffer_len * sizeof(uint32_t));
    ocall_debug_print(msg);

    ocall_debug_print("");
    for (int i = 0; i < d_buffer_len * sizeof(uint32_t); i++) {
        snprintf(msg, sizeof(msg), "%02x ", ((uint8_t * )(d_buffer))[i]);
        ocall_print(msg);
    }
    ocall_debug_print("");
    for (int i = d_buffer_len * sizeof(uint32_t) - 1; i >= 0; i--) {
        snprintf(msg, sizeof(msg), "%02x", ((uint8_t * )(d_buffer))[i]);
        ocall_print(msg);
    }
    ocall_print("\n\n");

    return 0;
}

int ecall_test() {
    ocall_debug_print("\n\n\n");
    ocall_debug_print("test called");
    ocall_debug_print("\n\n\n");

    char msg[256] = {0};

    int my_ret = ecall_common_initialise(10);
    snprintf(msg, sizeof(msg), "ecall_common_initialise returned %d", my_ret);
    ocall_debug_print(msg);

    snprintf(msg, sizeof(msg),
             "ec_order_size: %d, ec_order_bit_size: %d, ec_order_u32_size: %d, ec_context_size: %d",
             context_common.ec_order_size, context_common.ec_order_bit_size, context_common.ec_order_u32_size,
             context_common.ec_context_size);
    ocall_debug_print(msg);
    snprintf(msg, sizeof(msg), "bn_context_size: %d, point_context_size: %d", context_common.bn_context_size,
             context_common.point_context_size);
    ocall_debug_print(msg);

    my_ret = ecall_offline_t_initialise();
    snprintf(msg, sizeof(msg), "ecall_offline_t_initialise returned %d", my_ret);
    ocall_debug_print(msg);

    my_ret = ecall_offline_ca_initialise();
    snprintf(msg, sizeof(msg), "ecall_offline_ca_initialise returned %d", my_ret);
    ocall_debug_print(msg);

    uint32_t ws[10];
    for (int i = 0; i < 10; i++) {
        ws[i] = 0;
    }
    ws[3] = 10;
    ws[9] = 100;
    my_ret = ecall_offline_ca_set_ws_and_compute_Ws(ws);
    snprintf(msg, sizeof(msg), "ecall_offline_ca_set_ws_and_compute_Ws returned %d", my_ret);
    ocall_debug_print(msg);

    uint8_t d_data[32 + 2000] = {0};
    size_t d_data_size = sizeof(d_data);
    uint8_t Ws_data[10 * 32 * 2] = {0};
    my_ret = ecall_offline_ca_get_d_and_Ws(d_data, &d_data_size, Ws_data, sizeof(Ws_data));
    snprintf(msg, sizeof(msg), "ecall_offline_ca_get_d_and_Ws returned %d", my_ret);
    ocall_debug_print(msg);
    snprintf(msg, sizeof(msg), "d_data_size: %lu", d_data_size);
    ocall_debug_print(msg);

    my_ret = ecall_offline_t_set_Ws_and_compute_cts(Ws_data, sizeof(Ws_data));
    snprintf(msg, sizeof(msg), "ecall_offline_t_set_Ws_and_compute_cts returned %d", my_ret);
    ocall_debug_print(msg);

    uint8_t x_data[32 + 2000] = {0};
    size_t x_data_size = sizeof(x_data);
    uint8_t cts_data[10 * 32 * 4 + 2000] = {0};
    size_t cts_data_size = sizeof(cts_data);
    my_ret = ecall_offline_t_get_x_and_cts(x_data, &x_data_size, cts_data, &cts_data_size);
    snprintf(msg, sizeof(msg), "ecall_offline_t_get_x_and_cts returned %d", my_ret);
    ocall_debug_print(msg);
    snprintf(msg, sizeof(msg), "x_data_size: %lu, cts_data_size: %lu", x_data_size, cts_data_size);
    ocall_debug_print(msg);

    my_ret = ecall_online_t_initialise(x_data, x_data_size);
    snprintf(msg, sizeof(msg), "ecall_online_t_initialise returned %d", my_ret);
    ocall_debug_print(msg);

    uint8_t snps[10] = {0, 0, 0, 1, 0, 0, 0, 0, 0, 2};
    my_ret = ecall_online_u_initialise(snps);
    snprintf(msg, sizeof(msg), "ecall_online_u_initialise returned %d", my_ret);
    ocall_debug_print(msg);

    my_ret = ecall_online_ca_initialise(d_data, d_data_size);
    snprintf(msg, sizeof(msg), "ecall_online_ca_initialise returned %d", my_ret);
    ocall_debug_print(msg);

    uint8_t cts_data_unsealed[10 * 32 * 4] = {0};
    size_t cts_data_unsealed_size = sizeof(cts_data_unsealed);
    my_ret = ecall_online_t_unseal_cts(cts_data, cts_data_size, cts_data_unsealed, cts_data_unsealed_size);
    snprintf(msg, sizeof(msg), "ecall_online_t_unseal_cts returned %d", my_ret);
    ocall_debug_print(msg);

    my_ret = ecall_online_u_set_cts_and_compute_ctres_pres_sres(cts_data_unsealed, sizeof(cts_data_unsealed));
    snprintf(msg, sizeof(msg), "ecall_online_u_set_cts_and_compute_ctres_pres_sres returned %d", my_ret);
    ocall_debug_print(msg);

    uint8_t ctres_data[32 * 4];
    uint64_t pres_data;
    uint64_t sres_data;
    my_ret = ecall_online_u_get_ctres_pres_sres(ctres_data, &pres_data, &sres_data);
    snprintf(msg, sizeof(msg), "ecall_online_u_get_ctres_pres_sres returned %d", my_ret);
    ocall_debug_print(msg);

    /*ocall_debug_print("ctres:\n");
    for (int i = 0; i < sizeof(ctres_data); i++) {
        snprintf(msg, sizeof(msg), "0x%02x ", ctres_data[i]);
        ocall_print(msg);
    }
    ocall_print("\n\n");

    ocall_debug_print("pres:\n");
    for (int i = 0; i < sizeof(pres_data); i++) {
        snprintf(msg, sizeof(msg), "0x%02x ", ((uint8_t * )(&pres_data))[i]);
        ocall_print(msg);
    }
    ocall_print("\n\n");

    ocall_debug_print("sres:\n");
    for (int i = 0; i < sizeof(sres_data); i++) {
        snprintf(msg, sizeof(msg), "0x%02x ", ((uint8_t * )(&sres_data))[i]);
        ocall_print(msg);
    }
    ocall_print("\n\n");*/


    my_ret = ecall_online_ca_set_ctres_pres_sres_and_compute_res(ctres_data, &pres_data, &sres_data);
    snprintf(msg, sizeof(msg), "ecall_online_ca_set_ctres_pres_sres_and_compute_res returned %d", my_ret);
    ocall_debug_print(msg);

    uint8_t res_data[32 * 4];
    my_ret = ecall_online_ca_get_res(res_data);
    snprintf(msg, sizeof(msg), "ecall_online_ca_get_res returned %d", my_ret);
    ocall_debug_print(msg);

    ocall_debug_print("res:\n");
    for (int i = 0; i < sizeof(res_data); i++) {
        snprintf(msg, sizeof(msg), "0x%02x ", res_data[i]);
        ocall_print(msg);
    }
    ocall_print("\n\n");

    uint8_t result_data[32 * 2];
    my_ret = ecall_online_t_set_res_and_get_result(res_data, result_data);
    snprintf(msg, sizeof(msg), "ecall_online_t_set_res_and_get_result returned %d", my_ret);
    ocall_debug_print(msg);

    ocall_debug_print("result:\n");
    for (int i = 0; i < sizeof(result_data); i++) {
        snprintf(msg, sizeof(msg), "0x%02x ", result_data[i]);
        ocall_print(msg);
    }
    ocall_print("\n\n");

    uint64_t decoded_result = 0;
    my_ret = ecall_decode_result(result_data, &decoded_result);
    snprintf(msg, sizeof(msg), "ecall_decode_result returned %d", my_ret);
    ocall_debug_print(msg);
    ocall_print("\n\n");
    snprintf(msg, sizeof(msg), "decoded result: %lu", decoded_result);
    ocall_debug_print(msg);

    ocall_debug_print("\n\n\n");
    ocall_debug_print("test exiting");
    ocall_debug_print("\n\n\n");

    return 0;
}
