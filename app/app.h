/*
 * Copyright 2018 Alberto Sonnino
 * 
 * This file is part of MY-SGX.
 * 
 * MY-SGX is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * MY-SGX is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with MY-SGX.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef APP_H_
#define APP_H_


/***************************************************
 * config.
 ***************************************************/
#define APP_NAME "my-sgx"
#define VERSION "0.0.1"
#define ENCLAVE_FILE "enclave.signed.so"

#define X_FILE "x.data"
#define CTS_FILE "cts.data"
#define D_FILE "d.data"
#define RESULT_FILE "result.data"
#define DECODED_RESULT_FILE "result_decoded.txt"

#define EC_ORDER_BIT_SIZE 256
#define EC_ORDER_SIZE   EC_ORDER_BIT_SIZE / 8

#define MODE_UNDEFINED 0
#define MODE_OFFLINE_T 1
#define MODE_OFFLINE_CA 2
#define MODE_ONLINE_U 3
#define MODE_ONLINE_T 4
#define MODE_ONLINE_CA 5

#define X_SIZE  EC_ORDER_SIZE
#define D_SIZE  EC_ORDER_SIZE
#define CTRES_SIZE  EC_ORDER_SIZE * 4
#define PRES_SIZE   8
#define SRES_SIZE   8
#define RES_SIZE    EC_ORDER_SIZE * 4
#define RESULT_SIZE EC_ORDER_SIZE * 2

#define ws_size_from_n(n)   n * 4
#define cts_size_from_n(n)  n * EC_ORDER_SIZE * 4
#define Ws_size_from_n(n)   n * EC_ORDER_SIZE * 2
#define snps_size_from_n(n) n

#endif // APP_H_