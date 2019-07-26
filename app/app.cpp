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
#include "enclave_u.h"
#include "sgx_urts.h"

#include <cstring>
#include <fstream>
#include <getopt.h>

#include "app.h"
#include "utils.h"
#include "debug.h"
#include "wallet.h"
#include "enclave.h"
#include "test.h"
#include "ippcp.h"

using namespace std;


/***************************************************
 * OCALLs implementation
 ***************************************************/
/**
 * @brief      Prints a message to the console. 
 *
 */
void ocall_debug_print(const char *str) {
    printf("[DEBUG] %s\n", str);
}

/**
 * @brief      Save sealed data to file The sizes/length of 
 *             pointers need to be specified, otherwise SGX will
 *             assume a count of 1 for all pointers.
 *
 */
int ocall_save_wallet(const uint8_t *sealed_data, const size_t sealed_size) {
    ofstream file(WALLET_FILE, ios::out | ios::binary);
    if (file.fail()) { return 1; }
    file.write((const char *) sealed_data, sealed_size);
    file.close();
    return 0;
}

/**
 * @brief      Load sealed data from file The sizes/length of 
 *             pointers need to be specified, otherwise SGX will
 *             assume a count of 1 for all pointers.
 *
 */
int ocall_load_wallet(uint8_t *sealed_data, const size_t sealed_size) {
    ifstream file(WALLET_FILE, ios::in | ios::binary);
    if (file.fail()) { return 1; }
    file.read((char *) sealed_data, sealed_size);
    file.close();
    return 0;
}

/**
 * @brief      Verifies if a wallet files exists.
 *
 */
int ocall_is_wallet(void) {
    ifstream file(WALLET_FILE, ios::in | ios::binary);
    if (file.fail()) { return 0; } // failure means no wallet found
    file.close();
    return 1;
}


/***************************************************
 * main
 ***************************************************/
int main(int argc, char **argv) {
    // declare enclave & return variables
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    int updated, ret;
    sgx_status_t ecall_status, enclave_status;

    /*int psize = 0;
    IppStatus pstatus = ippsECCPGetSizeStd256r1(&psize);
    if (pstatus != ippStsNoErr) {
        ocall_debug_print("app: ippsECCPGetSizeStd256r1 failed");
        ocall_debug_print("\n\n\n");
        return -1;
    }
    char msg[100];
    snprintf(msg, sizeof(msg), "app: IppsECCPState size: %d", psize);
    ocall_debug_print(msg);*/

    ////////////////////////////////////////////////
    // initialise enclave
    ////////////////////////////////////////////////
    enclave_status = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (enclave_status != SGX_SUCCESS) {
        error_print("Fail to initialise enclave");
        return -1;
    }
    info_print("Enclave successfully initilised");

    /*ecall_status = ecall_test_crypto(eid, &ret);
    if (ecall_status != SGX_SUCCESS || is_error(ret)) {
        error_print("ecall_test_crypto failed.");
    } else {
        info_print("test_crypto succeded.");
    }

    ecall_status = ecall_common_initialise(eid, &ret, 1000);
    printf("ecall_status: %d, eid: %lu, ret: %d\n", ecall_status, eid, ret);*/

    ////////////////////////////////////////////////
    // read input arguments 
    ////////////////////////////////////////////////
    const char *options = "m:b:h:p:i:q:n:w:d:x:c:s:";
    //opterr = 0; // prevent 'getopt' from printing err messages
    //char err_message[100];
    int opt = 0;
    int m_flag = 0, b_flag = 0, h_flag = 0, p_flag = 0, i_flag = 0, q_flag = 0;
    int n_flag = 0, w_flag = 0, d_flag = 0, x_flag = 0, c_flag = 0, s_flag = 0;
    char *m_value = NULL, *b_value = NULL, *h_value = NULL, *p_value = NULL, *n_value = NULL, *i_value = NULL;
    char *q_value = NULL, *w_value = NULL, *d_value = NULL, *x_value = NULL, *c_value = NULL, *s_value = NULL;

    // read user input
    while ((opt = getopt(argc, argv, options)) != -1) {
        switch (opt) {
            // mode
            case 'm':
                m_flag = 1;
                m_value = optarg;
                break;

                // listening port
            case 'b':
                b_flag = 1;
                b_value = optarg;
                break;

                // CA server hostname
            case 'h':
                h_flag = 1;
                h_value = optarg;
                break;

                // CA server port
            case 'p':
                p_flag = 1;
                p_value = optarg;
                break;

                // T server hostname
            case 'i':
                i_flag = 1;
                i_value = optarg;
                break;

                // T server port
            case 'q':
                q_flag = 1;
                q_value = optarg;
                break;

                // number of SNPs/weights
            case 'n':
                n_flag = 1;
                n_value = optarg;
                break;

                // weights file
            case 'w':
                w_flag = 1;
                w_value = optarg;
                break;

                // d file
            case 'd':
                d_flag = 1;
                d_value = optarg;
                break;

                // x file
            case 'x':
                x_flag = 1;
                x_value = optarg;
                break;

                // cts file
            case 'c':
                c_flag = 1;
                c_value = optarg;
                break;

                // SNPs file
            case 's':
                s_flag = 1;
                s_value = optarg;
                break;

            default:
                error_print("Unknown option");
        }
    }

    ////////////////////////////////////////////////
    // perform actions
    ////////////////////////////////////////////////
    if (m_flag != 1) {
        error_print("Mode is missing");
        show_help();
        return -1;
    }

    if (strcmp(m_value, "offline_t") == 0) {
        if (h_flag != 1 || p_flag != 1 || n_flag != 1 || w_flag != 1) {
            error_print("Missing options");
            show_help();
            return -1;
        }

        info_print("Mode: Offline T");
        printf("CA hostname: %s, CA port: %s, n: %s, w file: %s\n", h_value, p_value, n_value, w_value);

    } else if (strcmp(m_value, "offline_ca") == 0) {
        if (b_flag != 1 || n_flag != 1) {
            error_print("Missing options");
            show_help();
            return -1;
        }

        info_print("Mode: Offline CA");
        printf("Listening port: %s, n: %s\n", b_value, n_value);

    } else if (strcmp(m_value, "online_u") == 0) {
        if (h_flag != 1 || p_flag != 1 || i_flag != 1 || q_flag != 1 || n_flag != 1 || s_flag != 1) {
            error_print("Missing options");
            show_help();
            return -1;
        }

        info_print("Mode: Offline CA");
        printf("CA hostname: %s, CA port: %s, T hostname: %s, T port: %s, n: %s, SNPs file: %s\n", h_value, p_value,
               i_value, q_value, n_value, s_value);

    } else if (strcmp(m_value, "online_t") == 0) {
        if (b_flag != 1 || n_flag != 1 || x_flag != 1 || c_flag != 1) {
            error_print("Missing options");
            show_help();
            return -1;
        }

        info_print("Mode: Online T");
        printf("Listening port: %s, n: %s, x file: %s, cts file: %s\n", b_value, n_value, x_value, c_value);

    } else if (strcmp(m_value, "online_ca") == 0) {
        if (b_flag != 1 || d_flag != 1) {
            error_print("Missing options");
            show_help();
            return -1;
        }

        info_print("Mode: Online CA");
        printf("Listening port: %s, d file: %s\n", b_value, d_value);

    } else {
        error_print("Mode is invalid");
        show_help();
        return -1;
    }


    /*if (stop != 1) {
        // show help
        if (h_flag) {
            show_help();
        }

            // show version
        else if (v_flag) {
            show_version();
        }

            // run tests
        else if (t_flag) {
            info_print("Running tests...");
            if (test(eid) != 0) { error_print("One or more tests failed."); }
            else { info_print("All tests successfully passed."); }
        }

            // create new wallet
        else if (n_value != NULL) {
            ecall_status = ecall_create_wallet(eid, &ret, n_value);
            if (ecall_status != SGX_SUCCESS || is_error(ret)) {
                error_print("Fail to create new wallet.");
            } else {
                info_print("Wallet successfully created.");
            }
        }

            // change master-password
        else if (p_value != NULL && c_value != NULL) {
            ecall_status = ecall_change_master_password(eid, &ret, p_value, c_value);
            if (ecall_status != SGX_SUCCESS || is_error(ret)) {
                error_print("Fail change master-password.");
            } else {
                info_print("Master-password successfully changed.");
            }
        }

            // show wallet
        else if (p_value != NULL && s_flag) {
            wallet_t *wallet = (wallet_t *) malloc(sizeof(wallet_t));
            ecall_status = ecall_show_wallet(eid, &ret, p_value, wallet, sizeof(wallet_t));
            if (ecall_status != SGX_SUCCESS || is_error(ret)) {
                error_print("Fail to retrieve wallet.");
            } else {
                info_print("Wallet successfully retrieved.");
                print_wallet(wallet);
            }
            free(wallet);
        }

            // add item
        else if (p_value != NULL && a_flag && x_value != NULL && y_value != NULL && z_value != NULL) {
            item_t *new_item = (item_t *) malloc(sizeof(item_t));
            strcpy(new_item->title, x_value);
            strcpy(new_item->username, y_value);
            strcpy(new_item->password, z_value);
            ecall_status = ecall_add_item(eid, &ret, p_value, new_item, sizeof(item_t));
            if (ecall_status != SGX_SUCCESS || is_error(ret)) {
                error_print("Fail to add new item to wallet.");
            } else {
                info_print("Item successfully added to the wallet.");
            }
            free(new_item);
        }

            // remove item
        else if (p_value != NULL && r_value != NULL) {
            char *p_end;
            int index = (int) strtol(r_value, &p_end, 10);
            if (r_value == p_end) {
                error_print("Option -r requires an integer argument.");
            } else {
                ecall_status = ecall_remove_item(eid, &ret, p_value, index);
                if (ecall_status != SGX_SUCCESS || is_error(ret)) {
                    error_print("Fail to remove item.");
                } else {
                    info_print("Item successfully removed from the wallet.");
                }
            }
        }

            // display help
        else {
            error_print("Wrong inputs.");
            show_help();
        }
    }*/

    ////////////////////////////////////////////////
    // destroy enclave
    ////////////////////////////////////////////////
    enclave_status = sgx_destroy_enclave(eid);
    if (enclave_status != SGX_SUCCESS) {
        error_print("Failed to destroy enclave");
        return -1;
    }
    info_print("Enclave successfully destroyed");

    ////////////////////////////////////////////////
    // exit success
    ////////////////////////////////////////////////
    info_print("Program exiting");
    return 0;
}
