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

#include "debug.h"
#include "enclave.h"
#include "wallet.h"

#include "sgx_tseal.h"
#include "sgx_tcrypto.h"
#include "sealing/sealing.h"

#include "stdio.h"
#include "ipp/ippcp.h"

static int hello = 0;

/*
 * T : Testing Facility
 * U : User
 * CA: Certification Authority
 */

#define EC_ORDER_BIT_SIZE 256

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
    IppsECCPPointState *result;
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
    IppsECCPPointState *result;
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
 * Offline operations for T
 */
int ecall_offline_t_initialise(); //Done

static int offline_t_initialise(struct common_context *common, struct offline_t_context *offline_t); //Done

int ecall_offline_t_set_Ws_and_compute_cts(const uint8_t *Ws_data, const size_t Ws_data_size); //Done

static int offline_t_set_Ws_and_compute_cts(struct common_context *common, struct offline_t_context *offline_t,
                                            const uint8_t *Ws_data, const size_t Ws_data_size); //Done

int ecall_offline_t_get_x_and_cts(uint8_t *x_data, uint8_t *cts_data, size_t cts_data_size); //Done

static int offline_t_get_x_and_cts(struct common_context *common, struct offline_t_context *offline_t, uint8_t *x_data,
                                   uint8_t *cts_data, size_t cts_data_size); //Done

/*
 * Offline operations for CA
 */
int ecall_offline_ca_initialise(); //Done

static int offline_ca_initialise(struct common_context *common, struct offline_ca_context *offline_ca); //Done

int ecall_offline_ca_set_ws_and_compute_Ws(uint32_t *ws); //Done

static int
offline_ca_set_ws_and_compute_Ws(struct common_context *common, struct offline_ca_context *offline_ca,
                                 uint32_t *ws); //Done

int ecall_offline_ca_get_d_and_Ws(uint8_t *d_data, uint8_t *Ws_data, size_t Ws_data_size); //Done

static int
offline_ca_get_d_and_Ws(struct common_context *common, struct offline_ca_context *offline_ca, uint8_t *d_data,
                        uint8_t *Ws_data, size_t Ws_data_size); //Done

/*
 * Online operations for T
 */
int ecall_online_t_initialise(const uint8_t *x_data); //Done

static int
online_t_initialise(struct common_context *common, struct online_t_context *online_t, const uint8_t *x_data); //Done

static void ecall_online_t_set_res_and_get_result(); //TODO

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
int ecall_online_ca_initialise(const uint8_t *d_data); //Done

static int
online_ca_initialise(struct common_context *common, struct online_ca_context *online_ca, const uint8_t *d_data); //Done

int ecall_online_ca_set_ctres_pres_sres_and_compute_res(const uint8_t *ctres_data, const uint64_t *pres_data,
                                                        const uint64_t *sres_data); //Done

static int online_ca_set_ctres_pres_sres_and_compute_res(struct common_context *common,
                                                         struct online_ca_context *online_ca, const uint8_t *ctres_data,
                                                         const uint64_t *pres_data, const uint64_t *sres_data); //Done

static void ecall_online_ca_get_res(); //TODO

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

    // set random value
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
    return bn_set_value(common, number, common->ec_order_u32_size, (const uint32_t *) rand_value);
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

int ecall_offline_t_set_Ws_and_compute_cts(const uint8_t *Ws_data, const size_t Ws_data_size) {
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
        size_t offset_x = i * common->ec_order_size;
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
        ipp_status = ippsECCPAddPoint(GxkW, Gk, GxkW, common->E);
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

int ecall_offline_t_get_x_and_cts(uint8_t *x_data, uint8_t *cts_data, size_t cts_data_size) {
    return offline_t_get_x_and_cts(&context_common, &context_offline_t, x_data, cts_data, cts_data_size);
}

static int offline_t_get_x_and_cts(struct common_context *common, struct offline_t_context *offline_t, uint8_t *x_data,
                                   uint8_t *cts_data, size_t cts_data_size) {
    if (cts_data != NULL && cts_data_size < common->n * common->ec_order_size * 4) {
        return -1;
    }

    int ipp_status = 0;

    if (x_data != NULL) {
        // extract value of x
        IppsBigNumSGN sign;
        int x_buffer_len = common->ec_order_u32_size;
        uint32_t x_buffer[x_buffer_len];

        ipp_status = ippsGet_BN(&sign, &x_buffer_len, x_buffer, offline_t->x);
        if (sign == IppsBigNumNEG || ipp_status != ippStsNoErr) {
            return -1;
        }

        memcpy(x_data, x_buffer, common->ec_order_size);
    }

    if (cts_data != NULL) {
        // extract values of cts
        IppsBigNumState *x = bn_create_state(common);
        if (x == NULL) {
            return -1;
        }
        IppsBigNumState *y = bn_create_state(common);
        if (y == NULL) {
            free(x);

            return -1;
        }

        for (uint32_t i = 0; i < common->n * 2; i++) {
            // get x and y coordinates from point
            ipp_status = ippsECCPGetPoint(x, y, offline_t->cts[i], common->E);

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

            size_t offset_x = i * common->ec_order_size;
            memcpy(cts_data + offset_x, p_buffer, common->ec_order_size);

            // extract y-coordinate
            ipp_status = ippsGet_BN(&sign, &p_buffer_len, p_buffer, y);
            if (sign == IppsBigNumNEG || ipp_status != ippStsNoErr) {
                free(x);
                free(y);

                return -1;
            }

            size_t offset_y = offset_x + common->ec_order_size;
            memcpy(cts_data + offset_y, p_buffer, common->ec_order_size);
        }

        free(x);
        free(y);
    }

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

    IppsBigNumState *bn_exponent = bn_create_state_double_size(common);
    if (bn_exponent == NULL) {
        free(Ws);
        free(bn_i_plus_w_plus_one);

        return -1;
    }

    int failed = 0;
    for (uint32_t i = 1; i <= common->n; i++) {
        // allocate memory for Wi
        IppsECCPPointState *W = point_create_state(common);
        Ws[i - 1] = W;
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

        int ipp_status = ippsMul_BN(offline_ca->e, bn_i_plus_w_plus_one, bn_exponent);
        if (ipp_status != ippStsNoErr) {
            failed = 1;
            break;
        }

        ipp_status = ippsECCPMulPointScalar(common->G, bn_exponent, W, common->E);
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

        free(Ws);
        free(bn_i_plus_w_plus_one);
        free(bn_exponent);

        return -1;
    }

    free(bn_i_plus_w_plus_one);
    free(bn_exponent);

    return 0;
}

int ecall_offline_ca_get_d_and_Ws(uint8_t *d_data, uint8_t *Ws_data, size_t Ws_data_size) {
    return offline_ca_get_d_and_Ws(&context_common, &context_offline_ca, d_data, Ws_data, Ws_data_size);
}

static int
offline_ca_get_d_and_Ws(struct common_context *common, struct offline_ca_context *offline_ca, uint8_t *d_data,
                        uint8_t *Ws_data, size_t Ws_data_size) {
    if (Ws_data != NULL && Ws_data_size < common->n * common->ec_order_size * 2) {
        return -1;
    }

    int ipp_status = 0;

    if (d_data != NULL) {
        // extract value of d
        IppsBigNumSGN sign;
        int d_buffer_len = common->ec_order_u32_size;
        uint32_t d_buffer[d_buffer_len];

        ipp_status = ippsGet_BN(&sign, &d_buffer_len, d_buffer, offline_ca->d);
        if (sign == IppsBigNumNEG || ipp_status != ippStsNoErr) {
            return -1;
        }

        memcpy(d_data, d_buffer, common->ec_order_size);
    }

    if (Ws_data != NULL) {
        // extract values of Ws
        IppsBigNumState *x = bn_create_state(common);
        if (x == NULL) {
            return -1;
        }
        IppsBigNumState *y = bn_create_state(common);
        if (y == NULL) {
            free(x);

            return -1;
        }

        for (uint32_t i = 0; i < common->n; i++) {
            // get x and y coordinates from point
            ipp_status = ippsECCPGetPoint(x, y, offline_ca->Ws[i], common->E);

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

            size_t offset_x = i * common->ec_order_size;
            memcpy(Ws_data + offset_x, p_buffer, common->ec_order_size);

            // extract y-coordinate
            ipp_status = ippsGet_BN(&sign, &p_buffer_len, p_buffer, y);
            if (sign == IppsBigNumNEG || ipp_status != ippStsNoErr) {
                free(x);
                free(y);

                return -1;
            }

            size_t offset_y = offset_x + common->ec_order_size;
            memcpy(Ws_data + offset_y, p_buffer, common->ec_order_size);
        }

        free(x);
        free(y);
    }

    return 0;
}

int ecall_online_t_initialise(const uint8_t *x_data) {
    return online_t_initialise(&context_common, &context_online_t, x_data);
}

static int
online_t_initialise(struct common_context *common, struct online_t_context *online_t, const uint8_t *x_data) {
    IppsBigNumState *x = bn_create_state(common);
    if (x == NULL) {
        return -1;
    }

    int ret = bn_set_value(common, x, common->ec_order_u32_size, (const uint32_t *) x_data);
    if (ret < 0) {
        free(x);

        return -1;
    }

    online_t->x = x;

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
            online_u->pres += index * snp;
            online_u->sres += snp;
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

            online_u->pres += index * snp;
            online_u->sres += snp;
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

int ecall_online_ca_initialise(const uint8_t *d_data) {
    return online_ca_initialise(&context_common, &context_online_ca, d_data);
}

static int
online_ca_initialise(struct common_context *common, struct online_ca_context *online_ca, const uint8_t *d_data) {
    IppsBigNumState *d = bn_create_state(common);
    if (d == NULL) {
        return -1;
    }
    online_ca->d = d;

    int ret = bn_set_value(common, d, common->ec_order_u32_size, (const uint32_t *) d_data);
    if (ret < 0) {
        free(d);

        return -1;
    }

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
    int ret = bn_set_value(common, ax, common->ec_order_u32_size, (const uint32_t *) (ctres_data));
    ret += bn_set_value(common, ay, common->ec_order_u32_size, (const uint32_t *) (ctres_data + common->ec_order_size));
    ret += bn_set_value(common, bx, common->ec_order_u32_size,
                        (const uint32_t *) (ctres_data + (common->ec_order_size * 2)));
    ret += bn_set_value(common, bx, common->ec_order_u32_size,
                        (const uint32_t *) (ctres_data + (common->ec_order_size * 3)));
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

void test_print() {
    ocall_debug_print("test_print called");
}

int ecall_test_crypto() {
    ocall_debug_print("\n\n\n");
    ocall_debug_print("test_crypto called");
    ocall_debug_print("\n\n\n");

    char msg[256] = {0};

    int my_ret = ecall_common_initialise(1000);
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

    uint32_t ws[1000];
    for (int i = 0; i < 1000; i++) {
        ws[i] = i;
    }
    my_ret = ecall_offline_ca_set_ws_and_compute_Ws(ws);
    snprintf(msg, sizeof(msg), "ecall_offline_ca_set_ws_and_compute_Ws returned %d", my_ret);
    ocall_debug_print(msg);

    uint8_t d_data[32] = {0};
    uint8_t Ws_data[1000 * 32 * 2] = {0};
    my_ret = ecall_offline_ca_get_d_and_Ws(d_data, Ws_data, sizeof(Ws_data));
    snprintf(msg, sizeof(msg), "ecall_offline_ca_get_d_and_Ws returned %d", my_ret);
    ocall_debug_print(msg);

    my_ret = ecall_offline_t_set_Ws_and_compute_cts(Ws_data, sizeof(Ws_data));
    snprintf(msg, sizeof(msg), "ecall_offline_t_set_Ws_and_compute_cts returned %d", my_ret);
    ocall_debug_print(msg);

    uint8_t x_data[32] = {0};
    uint8_t cts_data[1000 * 32 * 4] = {0};
    my_ret = ecall_offline_t_get_x_and_cts(x_data, cts_data, sizeof(cts_data));
    snprintf(msg, sizeof(msg), "ecall_offline_t_get_x_and_cts returned %d", my_ret);
    ocall_debug_print(msg);

    my_ret = ecall_online_t_initialise(x_data);
    snprintf(msg, sizeof(msg), "ecall_online_t_initialise returned %d", my_ret);
    ocall_debug_print(msg);

    uint8_t snps[1000];
    for (int i = 0; i < 300; i++) {
        snps[i] = 0;
    }
    for (int i = 300; i < 600; i++) {
        snps[i] = 1;
    }
    for (int i = 600; i < 1000; i++) {
        snps[i] = 2;
    }
    my_ret = ecall_online_u_initialise(snps);
    snprintf(msg, sizeof(msg), "ecall_online_u_initialise returned %d", my_ret);
    ocall_debug_print(msg);

    my_ret = ecall_online_ca_initialise(d_data);
    snprintf(msg, sizeof(msg), "ecall_online_ca_initialise returned %d", my_ret);
    ocall_debug_print(msg);

    my_ret = ecall_online_u_set_cts_and_compute_ctres_pres_sres(cts_data, sizeof(cts_data));
    snprintf(msg, sizeof(msg), "ecall_online_u_set_cts_and_compute_ctres_pres_sres returned %d", my_ret);
    ocall_debug_print(msg);

    uint8_t ctres_data[32 * 4];
    uint64_t pres_data;
    uint64_t sres_data;
    my_ret = ecall_online_u_get_ctres_pres_sres(ctres_data, &pres_data, &sres_data);
    snprintf(msg, sizeof(msg), "ecall_online_u_get_ctres_pres_sres returned %d", my_ret);
    ocall_debug_print(msg);

    my_ret = ecall_online_ca_set_ctres_pres_sres_and_compute_res(ctres_data, &pres_data, &sres_data);
    snprintf(msg, sizeof(msg), "ecall_online_ca_set_ctres_pres_sres_and_compute_res returned %d", my_ret);
    ocall_debug_print(msg);


    ocall_debug_print("\n\n\n");
    ocall_debug_print("test_crypto exiting");
    ocall_debug_print("\n\n\n");

    return 1;

    test_print();

    sgx_status_t ret;

    snprintf(msg, sizeof(msg), "hello value : %d", hello);
    ocall_debug_print(msg);

    hello = 1;

    snprintf(msg, sizeof(msg), "hello value : %d", hello);
    ocall_debug_print(msg);

    /* Test random number generation */
    uint32_t rval = 0;
    ret = sgx_read_rand((unsigned char *) &rval, sizeof(rval));
    if (ret != SGX_SUCCESS) {
        ocall_debug_print("sgx_read_rand failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    }

    snprintf(msg, sizeof(msg), "random number: %u", rval);
    ocall_debug_print(msg);

    /* Test IPP */
    int psize = 0;
    IppStatus pstatus;

    // get IppsECCPState context size in bytes
    pstatus = ippsECCPGetSizeStd256r1(&psize);
    if (pstatus != ippStsNoErr) {
        ocall_debug_print("ippsECCPGetSizeStd256r1 failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    }
    snprintf(msg, sizeof(msg), "IppsECCPState size: %d", psize);
    ocall_debug_print(msg);

    // allocate memory for ec context
    IppsECCPState *ec = (IppsECCPState *) malloc(psize);
    if (ec == NULL) {
        ocall_debug_print("malloc failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    }

    // initialise ec context
    pstatus = ippsECCPInitStd256r1(ec);
    if (pstatus != ippStsNoErr) {
        ocall_debug_print("ippsECCPInitStd256r1 failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    } else {
        ocall_debug_print("ippsECCPInitStd256r1 succeeded");
    }

    // set ec context
    pstatus = ippsECCPSetStd256r1(ec);
    if (pstatus != ippStsNoErr) {
        ocall_debug_print("ippsECCPSetStd256r1 failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    } else {
        ocall_debug_print("ippsECCPSetStd256r1 succeeded");
    }

    // get ec order bit size
    int ec_order_bit_size = 0;
    pstatus = ippsECCPGetOrderBitSize(&ec_order_bit_size, ec);
    if (pstatus != ippStsNoErr) {
        ocall_debug_print("ippsECCPGetOrderBitSize failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    }

    int ec_order_size = 1 + ((ec_order_bit_size - 1) / 8);

    snprintf(msg, sizeof(msg), "EC order bit size: %d", ec_order_bit_size);
    ocall_debug_print(msg);

    snprintf(msg, sizeof(msg), "EC order size: %d", ec_order_size);
    ocall_debug_print(msg);

    // get IppsBigNumState context size in bytes
    int bnsize = 0;

    pstatus = ippsBigNumGetSize(ec_order_size, &bnsize);
    if (pstatus != ippStsNoErr) {
        ocall_debug_print("ippsBigNumGetSize failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    }
    snprintf(msg, sizeof(msg), "IppsBigNumState size: %d", bnsize);
    ocall_debug_print(msg);

    // allocate memory for bn
    int cofactor = 0;

    IppsBigNumState *tmp = (IppsBigNumState *) malloc(bnsize);
    if (tmp == NULL) {
        ocall_debug_print("malloc failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    }
    pstatus = ippsBigNumInit(ec_order_size, tmp);
    if (pstatus != ippStsNoErr) {
        ocall_debug_print("ippsBigNumInit failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    }

    IppsBigNumState *q = (IppsBigNumState *) malloc(bnsize);
    if (q == NULL) {
        ocall_debug_print("malloc failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    }
    pstatus = ippsBigNumInit(ec_order_size, q);
    if (pstatus != ippStsNoErr) {
        ocall_debug_print("ippsBigNumInit failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    }

    IppsBigNumState *gx = (IppsBigNumState *) malloc(bnsize);
    if (gx == NULL) {
        ocall_debug_print("malloc failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    }
    pstatus = ippsBigNumInit(ec_order_size, gx);
    if (pstatus != ippStsNoErr) {
        ocall_debug_print("ippsBigNumInit failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    }

    IppsBigNumState *gy = (IppsBigNumState *) malloc(bnsize);
    if (gy == NULL) {
        ocall_debug_print("malloc failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    }
    pstatus = ippsBigNumInit(ec_order_size, gy);
    if (pstatus != ippStsNoErr) {
        ocall_debug_print("ippsBigNumInit failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    }

    IppsBigNumState *d = (IppsBigNumState *) malloc(bnsize);
    if (d == NULL) {
        ocall_debug_print("malloc d failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    }
    pstatus = ippsBigNumInit(ec_order_size, d);
    if (pstatus != ippStsNoErr) {
        ocall_debug_print("ippsBigNumInit d failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    }

    IppsBigNumState *e = (IppsBigNumState *) malloc(bnsize);
    if (e == NULL) {
        ocall_debug_print("malloc e failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    }
    pstatus = ippsBigNumInit(ec_order_size, e);
    if (pstatus != ippStsNoErr) {
        ocall_debug_print("ippsBigNumInit e failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    }

    // get q, gx, gy
    pstatus = ippsECCPGet(tmp, tmp, tmp, gx, gy, q, &cofactor, ec);
    if (pstatus != ippStsNoErr) {
        ocall_debug_print("ippsECCPGet failed");
        ocall_debug_print(ippcpGetStatusString(pstatus));
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    } else {
        ocall_debug_print("ippsECCPGet succeeded");
    }

    //free(tmp);

    // get G

    // get IppsECCPPoint context size in bytes
    int ecpsize;
    pstatus = ippsECCPPointGetSize(ec_order_bit_size, &ecpsize);
    if (pstatus != ippStsNoErr) {
        ocall_debug_print("ippsECCPPointGetSize failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    }
    snprintf(msg, sizeof(msg), "IppsECCPPointState size: %d", ecpsize);
    ocall_debug_print(msg);

    // allocate memory for point context
    IppsECCPPointState *G = (IppsECCPPointState *) malloc(ecpsize);
    if (G == NULL) {
        ocall_debug_print("malloc failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    }

    // initialise point context
    pstatus = ippsECCPPointInit(ec_order_bit_size, G);
    if (pstatus != ippStsNoErr) {
        ocall_debug_print("ippsECCPPointInit failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    } else {
        ocall_debug_print("ippsECCPPointInit succeeded");
    }

    // set point context
    pstatus = ippsECCPSetPoint(gx, gy, G, ec);
    if (pstatus != ippStsNoErr) {
        ocall_debug_print("ippsECCPSetPoint failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    } else {
        ocall_debug_print("ippsECCPSetPoint succeeded");
    }

    // check point on ec
    IppECResult cpres;
    pstatus = ippsECCPCheckPoint(G, &cpres, ec);
    if (pstatus != ippStsNoErr || cpres != ippECValid) {
        ocall_debug_print("ippsECCPCheckPoint failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    } else {
        ocall_debug_print("ippsECCPCheckPoint succeeded");
    }

    // generate d
    Ipp32u ddata[ec_order_size / sizeof(Ipp32u)];
    ret = sgx_read_rand((unsigned char *) &rval, ec_order_size);
    if (ret != SGX_SUCCESS) {
        ocall_debug_print("sgx_read_rand failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    }
    pstatus = ippsSet_BN(IppsBigNumPOS, sizeof(ddata) / sizeof(Ipp32u), ddata, d);
    if (pstatus != ippStsNoErr) {
        ocall_debug_print("ippsSet_BN failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    } else {
        ocall_debug_print("ippsSet_BN succeeded");
    }

    // generate e
    pstatus = ippsModInv_BN(d, q, e);
    if (pstatus != ippStsNoErr) {
        ocall_debug_print("ippsModInv_BN failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    } else {
        ocall_debug_print("ippsModInv_BN succeeded");
    }


    // check if inv of e == d
    pstatus = ippsModInv_BN(e, q, tmp);
    if (pstatus != ippStsNoErr) {
        ocall_debug_print("ippsModInv_BN failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    } else {
        ocall_debug_print("ippsModInv_BN succeeded");
    }
    Ipp32u comres;
    pstatus = ippsCmp_BN(tmp, d, &comres);
    if (pstatus != ippStsNoErr || comres != IS_ZERO) {
        ocall_debug_print("ippsCmp_BN failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    } else {
        ocall_debug_print("ippsCmp_BN succeeded");
    }

    pstatus = ippsCmpZero_BN(tmp, &comres);
    if (pstatus != ippStsNoErr || comres != GREATER_THAN_ZERO) {
        ocall_debug_print("ippsCmpZero_BN failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    } else {
        ocall_debug_print("ippsCmpZero_BN succeeded");
    }

    pstatus = ippsCmpZero_BN(d, &comres);
    if (pstatus != ippStsNoErr || comres != GREATER_THAN_ZERO) {
        ocall_debug_print("ippsCmpZero_BN failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    } else {
        ocall_debug_print("ippsCmpZero_BN succeeded");
    }

    pstatus = ippsCmpZero_BN(e, &comres);
    if (pstatus != ippStsNoErr || comres != GREATER_THAN_ZERO) {
        ocall_debug_print("ippsCmpZero_BN failed");
        ocall_debug_print("\n\n\n");
        return ERR_FAIL_SEAL;
    } else {
        ocall_debug_print("ippsCmpZero_BN succeeded");
    }

    ocall_debug_print("test_crypto exiting");
    ocall_debug_print("\n\n\n");

    return RET_SUCCESS;
}

/**
 * @brief      Creates a new wallet with the provided master-password.
 *
 */
int ecall_create_wallet(const char *master_password) {

    //
    // OVERVIEW:
    //	1. check password policy
    //	2. [ocall] abort if wallet already exist
    //	3. create wallet
    //	4. seal wallet
    //	5. [ocall] save wallet
    //	6. exit enclave
    //
    //
    sgx_status_t ocall_status, sealing_status;
    int ocall_ret;

    DEBUG_PRINT("CREATING NEW WALLET...");


    // 1. check passaword policy
    if (strlen(master_password) < 8 || strlen(master_password) + 1 > MAX_ITEM_SIZE) {
        return ERR_PASSWORD_OUT_OF_RANGE;
    }
    DEBUG_PRINT("[OK] Password policy successfully checked.");


    // 2. abort if wallet already exist
    ocall_status = ocall_is_wallet(&ocall_ret);
    if (ocall_ret != 0) {
        return ERR_WALLET_ALREADY_EXISTS;
    }
    DEBUG_PRINT("[OK] No pre-existing wallets.");


    // 3. create new wallet
    wallet_t *wallet = (wallet_t *) malloc(sizeof(wallet_t));
    wallet->size = 0;
    strncpy(wallet->master_password, master_password, strlen(master_password) + 1);
    DEBUG_PRINT("[OK] New wallet successfully created.");


    // 4. seal wallet
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(wallet_t);
    uint8_t *sealed_data = (uint8_t *) malloc(sealed_size);
    sealing_status = seal_wallet(wallet, (sgx_sealed_data_t *) sealed_data, sealed_size);
    free(wallet);
    if (sealing_status != SGX_SUCCESS) {
        free(sealed_data);
        return ERR_FAIL_SEAL;
    }
    DEBUG_PRINT("[OK] Seal wallet.");


    // 5. save wallet
    ocall_status = ocall_save_wallet(&ocall_ret, sealed_data, sealed_size);
    free(sealed_data);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
        return ERR_CANNOT_SAVE_WALLET;
    }
    DEBUG_PRINT("[OK] New wallet successfully saved.");


    // 6. exit enclave
    DEBUG_PRINT("WALLET SUCCESSFULLY CREATED.");
    return RET_SUCCESS;
}


/**
 * @brief      Provides the wallet content. The sizes/length of 
 *             pointers need to be specified, otherwise SGX will
 *             assume a count of 1 for all pointers.
 *
 */
int ecall_show_wallet(const char *master_password, wallet_t *wallet, size_t wallet_size) {

    //
    // OVERVIEW:
    //	1. [ocall] load wallet
    // 	2. unseal wallet
    //	3. verify master-password
    //	4. return wallet to app
    //	5. exit enclave
    //
    //
    sgx_status_t ocall_status, sealing_status;
    int ocall_ret;

    DEBUG_PRINT("RETURNING WALLET TO APP...");


    // 1. load wallet
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(wallet_t);
    uint8_t *sealed_data = (uint8_t *) malloc(sealed_size);
    ocall_status = ocall_load_wallet(&ocall_ret, sealed_data, sealed_size);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
        free(sealed_data);
        return ERR_CANNOT_LOAD_WALLET;
    }
    DEBUG_PRINT("[ok] Wallet successfully loaded.");


    // 2. unseal loaded wallet
    uint32_t plaintext_size = sizeof(wallet_t);
    wallet_t *unsealed_wallet = (wallet_t *) malloc(plaintext_size);
    sealing_status = unseal_wallet((sgx_sealed_data_t *) sealed_data, unsealed_wallet, plaintext_size);
    free(sealed_data);
    if (sealing_status != SGX_SUCCESS) {
        free(unsealed_wallet);
        return ERR_FAIL_UNSEAL;
    }
    DEBUG_PRINT("[OK] Unseal wallet.");


    // 3. verify master-password
    if (strcmp(unsealed_wallet->master_password, master_password) != 0) {
        free(unsealed_wallet);
        return ERR_WRONG_MASTER_PASSWORD;
    }
    DEBUG_PRINT("[ok] Master-password successfully verified.");


    // 4. return wallet to app
    (*wallet) = *unsealed_wallet;
    free(unsealed_wallet);
    DEBUG_PRINT("[ok] Wallet successfully saved to buffer.");


    // 5. exit enclave
    DEBUG_PRINT("WALLET SUCCESSFULLY RETURNED TO APP.");
    return RET_SUCCESS;
}


/**
 * @brief      Changes the wallet's master-password.
 *
 */
int ecall_change_master_password(const char *old_password, const char *new_password) {

    //
    // OVERVIEW:
    //	1. check password policy
    //	2. [ocall] load wallet
    // 	3. unseal wallet
    //	4. verify old password
    //	5. update password
    //	6. seal wallet
    // 	7. [ocall] save sealed wallet
    //	8. exit enclave
    //
    //
    sgx_status_t ocall_status, sealing_status;
    int ocall_ret;

    DEBUG_PRINT("CHANGING MASTER PASSWORD...");


    // 1. check passaword policy
    if (strlen(new_password) < 8 || strlen(new_password) + 1 > MAX_ITEM_SIZE) {
        return ERR_PASSWORD_OUT_OF_RANGE;
    }
    DEBUG_PRINT("[ok] Password policy successfully checked.");


    // 2. load wallet
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(wallet_t);
    uint8_t *sealed_data = (uint8_t *) malloc(sealed_size);
    ocall_status = ocall_load_wallet(&ocall_ret, sealed_data, sealed_size);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
        free(sealed_data);
        return ERR_CANNOT_LOAD_WALLET;
    }
    DEBUG_PRINT("[ok] Wallet successfully loaded.");


    // 3. unseal wallet
    uint32_t plaintext_size = sizeof(wallet_t);
    wallet_t *wallet = (wallet_t *) malloc(plaintext_size);
    sealing_status = unseal_wallet((sgx_sealed_data_t *) sealed_data, wallet, plaintext_size);
    free(sealed_data);
    if (sealing_status != SGX_SUCCESS) {
        free(wallet);
        return ERR_FAIL_UNSEAL;
    }
    DEBUG_PRINT("[OK] Unseal wallet.");


    // 4. verify master-password
    if (strcmp(wallet->master_password, old_password) != 0) {
        free(wallet);
        return ERR_WRONG_MASTER_PASSWORD;
    }
    DEBUG_PRINT("[ok] Master-password successfully verified.");


    // 5. update password
    strncpy(wallet->master_password, new_password, strlen(new_password) + 1);
    DEBUG_PRINT("[ok] Successfully updated master-password.");


    // 6. seal wallet
    sealed_data = (uint8_t *) malloc(sealed_size);
    sealing_status = seal_wallet(wallet, (sgx_sealed_data_t *) sealed_data, sealed_size);
    free(wallet);
    if (sealing_status != SGX_SUCCESS) {
        free(wallet);
        free(sealed_data);
        return ERR_FAIL_SEAL;
    }
    DEBUG_PRINT("[OK] Seal wallet.");


    // 7. save wallet
    ocall_status = ocall_save_wallet(&ocall_ret, sealed_data, sealed_size);
    free(sealed_data);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
        return ERR_CANNOT_SAVE_WALLET;
    }
    DEBUG_PRINT("[OK] Wallet successfully saved.");


    // 6. exit enclave
    DEBUG_PRINT("MASTER PASSWORD SUCCESSFULLY CHANGED.");
    return RET_SUCCESS;
}


/**
 * @brief      Adds an item to the wallet. The sizes/length of 
 *             pointers need to be specified, otherwise SGX will
 *             assume a count of 1 for all pointers.
 *
 */
int ecall_add_item(const char *master_password, const item_t *item, const size_t item_size) {

    //
    // OVERVIEW:
    //	1. [ocall] load wallet
    //	2. unseal wallet
    //	3. verify master-password
    //	4. check input length
    //	5. add item to the wallet
    //	6. seal wallet
    //	7. [ocall] save sealed wallet
    //	8. exit enclave
    //
    //
    sgx_status_t ocall_status, sealing_status;
    int ocall_ret;

    DEBUG_PRINT("ADDING ITEM TO THE WALLET...");


    // 2. load wallet
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(wallet_t);
    uint8_t *sealed_data = (uint8_t *) malloc(sealed_size);
    ocall_status = ocall_load_wallet(&ocall_ret, sealed_data, sealed_size);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
        free(sealed_data);
        return ERR_CANNOT_LOAD_WALLET;
    }
    DEBUG_PRINT("[ok] Wallet successfully loaded.");


    // 3. unseal wallet
    uint32_t plaintext_size = sizeof(wallet_t);
    wallet_t *wallet = (wallet_t *) malloc(plaintext_size);
    sealing_status = unseal_wallet((sgx_sealed_data_t *) sealed_data, wallet, plaintext_size);
    free(sealed_data);
    if (sealing_status != SGX_SUCCESS) {
        free(wallet);
        return ERR_FAIL_UNSEAL;
    }
    DEBUG_PRINT("[OK] Unseal wallet.");


    // 3. verify master-password
    if (strcmp(wallet->master_password, master_password) != 0) {
        free(wallet);
        return ERR_WRONG_MASTER_PASSWORD;
    }
    DEBUG_PRINT("[ok] Master-password successfully verified.");


    // 4. check input length
    if (strlen(item->title) + 1 > MAX_ITEM_SIZE ||
        strlen(item->username) + 1 > MAX_ITEM_SIZE ||
        strlen(item->password) + 1 > MAX_ITEM_SIZE
            ) {
        free(wallet);
        return ERR_ITEM_TOO_LONG;
    }
    DEBUG_PRINT("[ok] Item successfully verified.");


    // 5. add item to the wallet
    size_t wallet_size = wallet->size;
    if (wallet_size >= MAX_ITEMS) {
        free(wallet);
        return ERR_WALLET_FULL;
    }
    wallet->items[wallet_size] = *item;
    ++wallet->size;
    DEBUG_PRINT("[OK] Item successfully added.");


    // 6. seal wallet
    sealed_data = (uint8_t *) malloc(sealed_size);
    sealing_status = seal_wallet(wallet, (sgx_sealed_data_t *) sealed_data, sealed_size);
    free(wallet);
    if (sealing_status != SGX_SUCCESS) {
        free(wallet);
        free(sealed_data);
        return ERR_FAIL_SEAL;
    }
    DEBUG_PRINT("[OK] Seal wallet.");


    // 7. save wallet
    ocall_status = ocall_save_wallet(&ocall_ret, sealed_data, sealed_size);
    free(sealed_data);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
        return ERR_CANNOT_SAVE_WALLET;
    }
    DEBUG_PRINT("[OK] Wallet successfully saved.");


    // 8. exit enclave
    DEBUG_PRINT("ITEM SUCCESSFULLY ADDED TO THE WALLET.");
    return RET_SUCCESS;
}


/**
 * @brief      Removes an item from the wallet. The sizes/length of 
 *             pointers need to be specified, otherwise SGX will
 *             assume a count of 1 for all pointers.
 *
 */
int ecall_remove_item(const char *master_password, const int index) {

    //
    // OVERVIEW:
    //	1. check index bounds
    //	2. [ocall] load wallet
    //	3. unseal wallet
    //	4. verify master-password
    //	5. remove item from the wallet
    //	6. seal wallet
    //	7. [ocall] save sealed wallet
    //	8. exit enclave
    //
    //
    sgx_status_t ocall_status, sealing_status;
    int ocall_ret;

    DEBUG_PRINT("REMOVING ITEM FROM THE WALLET...");


    // 1. check index bounds
    if (index < 0 || index >= MAX_ITEMS) {
        return ERR_ITEM_DOES_NOT_EXIST;
    }
    DEBUG_PRINT("[OK] Successfully checked index bounds.");


    // 2. load wallet
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(wallet_t);
    uint8_t *sealed_data = (uint8_t *) malloc(sealed_size);
    ocall_status = ocall_load_wallet(&ocall_ret, sealed_data, sealed_size);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
        free(sealed_data);
        return ERR_CANNOT_LOAD_WALLET;
    }
    DEBUG_PRINT("[ok] Wallet successfully loaded.");


    // 3. unseal wallet
    uint32_t plaintext_size = sizeof(wallet_t);
    wallet_t *wallet = (wallet_t *) malloc(plaintext_size);
    sealing_status = unseal_wallet((sgx_sealed_data_t *) sealed_data, wallet, plaintext_size);
    free(sealed_data);
    if (sealing_status != SGX_SUCCESS) {
        free(wallet);
        return ERR_FAIL_UNSEAL;
    }
    DEBUG_PRINT("[OK] Unseal wallet.");


    // 4. verify master-password
    if (strcmp(wallet->master_password, master_password) != 0) {
        free(wallet);
        return ERR_WRONG_MASTER_PASSWORD;
    }
    DEBUG_PRINT("[ok] Master-password successfully verified.");


    // 5. remove item from the wallet
    size_t wallet_size = wallet->size;
    if (index >= wallet_size) {
        free(wallet);
        return ERR_ITEM_DOES_NOT_EXIST;
    }
    for (int i = index; i < wallet_size - 1; ++i) {
        wallet->items[i] = wallet->items[i + 1];
    }
    --wallet->size;
    DEBUG_PRINT("[OK] Item successfully removed.");


    // 6. seal wallet
    sealed_data = (uint8_t *) malloc(sealed_size);
    sealing_status = seal_wallet(wallet, (sgx_sealed_data_t *) sealed_data, sealed_size);
    free(wallet);
    if (sealing_status != SGX_SUCCESS) {
        free(sealed_data);
        return ERR_FAIL_SEAL;
    }
    DEBUG_PRINT("[OK] Seal wallet.");


    // 7. save wallet
    ocall_status = ocall_save_wallet(&ocall_ret, sealed_data, sealed_size);
    free(sealed_data);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
        return ERR_CANNOT_SAVE_WALLET;
    }
    DEBUG_PRINT("[OK] Wallet successfully saved.");


    // 8. exit enclave
    DEBUG_PRINT("ITEM SUCCESSFULLY REMOVED FROM THE WALLET.");
    return RET_SUCCESS;
}

