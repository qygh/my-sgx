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
    IppsECCPPointState **cts;

    // res: Pair of points
    IppsECCPPointState **res;

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
    IppsECCPPointState **cts;

    // ctres: Pair of points
    IppsECCPPointState **ctres;

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
    IppsECCPPointState **ctres;

    // pres: Long (64 bits)
    uint64_t pres;

    // sres: Long (64 bits)
    uint64_t sres;

    // res: Pair of points
    IppsECCPPointState **res;
};

/*
 * Global structures
 */
static struct common_context context_common = {0};

static struct offline_t_context context_offline_t = {0};

static struct offline_ca_context context_offline_ca = {0};

/*
 * Utils
 */
static IppsBigNumState *bn_create_state(struct common_context *common);

static IppsBigNumState *bn_create_state_double_size(struct common_context *common);

static int bn_set_value(struct common_context *common, IppsBigNumState *number, int u32_size);

static int bn_set_value_u32(struct common_context *common, IppsBigNumState *number, uint32_t value);

static int bn_set_value_random(struct common_context *common, IppsBigNumState *number);

static IppsECCPPointState *point_create_state(struct common_context *common);

/*
 * Common input: E, q, G, n
 */
int ecall_common_initialise(uint32_t n);

static int common_initialise(struct common_context *common, uint32_t n);

/*
 * Offline operations for T
 */
int ecall_offline_t_initialise();

static int offline_t_initialise(struct common_context *common, struct offline_t_context *offline_t);

static void ecall_offline_t_set_Ws_and_compute_cts();

static void ecall_offline_t_get_x_and_cts();

/*
 * Offline operations for CA
 */
int ecall_offline_ca_initialise();

static int offline_ca_initialise(struct common_context *common, struct offline_ca_context *offline_ca);

int ecall_offline_ca_set_ws_and_compute_Ws(uint32_t *ws);

static int
offline_ca_set_ws_and_compute_Ws(struct common_context *common, struct offline_ca_context *offline_ca, uint32_t *ws);

static void ecall_offline_ca_get_d_and_Ws();

/*
 * Online operations for T
 */
static void ecall_online_t_set_initial_input();

static void ecall_online_t_decrypt_res();

/*
 * Online operations for U
 */
static void ecall_online_u_set_initial_input();

static void ecall_online_u_compute_ctres_pres_sres();

/*
 * Online operations for CA
 */
static void ecall_online_ca_set_initial_input();

static void ecall_online_ca_compute_res();

/*
 * Create a BigNum state
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
 * Set a BigNum to random value
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

void test_print() {
    ocall_debug_print("test_print called");
}

int ecall_test_crypto() {
    ocall_debug_print("\n\n\n");
    ocall_debug_print("test_crypto called");
    ocall_debug_print("\n\n\n");

    char msg[256] = {0};

    int my_ret = ecall_common_initialise(32);
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

