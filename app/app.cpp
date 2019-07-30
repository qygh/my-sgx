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
#include <pthread.h>

#include "app.h"
#include "utils.h"
#include "debug.h"
#include "wallet.h"
#include "enclave.h"
#include "test.h"
#include "ippcp.h"

#include "offline_t_handler.h"
#include "offline_ca_handler.h"
#include "online_u_handler.h"
#include "online_t_handler.h"
#include "online_ca_handler.h"

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

int test_ecall() {
    // declare enclave & return variables
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    sgx_status_t ecall_status, enclave_status;
    int updated, ret;

    ////////////////////////////////////////////////
    // initialise enclave
    ////////////////////////////////////////////////
    enclave_status = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (enclave_status != SGX_SUCCESS) {
        error_print("Failed to initialise enclave");
        return -1;
    }
    info_print("Enclave successfully initilised");

    ecall_status = ecall_test(eid, &ret);
    if (ecall_status != SGX_SUCCESS || ret < 0) {
        error_print("Failed to run ecall_test()");

        sgx_destroy_enclave(eid);
        return -1;
    }
    printf("ecall_test() returnd %d\n", ret);

    ////////////////////////////////////////////////
    // destroy enclave
    ////////////////////////////////////////////////
    enclave_status = sgx_destroy_enclave(eid);
    if (enclave_status != SGX_SUCCESS) {
        error_print("Failed to destroy enclave");
        return -1;
    }
    info_print("Enclave successfully destroyed");

    return 0;
}

/***************************************************
 * main
 ***************************************************/
int main(int argc, char **argv) {
    // ignore SIGPIPE that can be possibly caused by writes to disconnected sockets
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        fprintf(stderr, "signal(): %s\n", strerror(errno));
    }

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
    const char *m_value = NULL, *b_value = NULL, *h_value = NULL, *p_value = NULL, *n_value = NULL, *i_value = NULL;
    const char *q_value = NULL, *w_value = NULL, *d_value = NULL, *x_value = NULL, *c_value = NULL, *s_value = NULL;

    int mode = MODE_UNDEFINED;

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
        return 1;
    }

    if (strcmp(m_value, "test") == 0) {
        int ret = test_ecall();
        printf("test_ecall returned %d\n", ret);
        if (ret < 0) {
            return 1;
        }

        return 0;

    } else if (strcmp(m_value, "offline_t") == 0) {
        if (h_flag != 1 || p_flag != 1 || n_flag != 1 || w_flag != 1) {
            error_print("Missing options");
            show_help();
            return 1;
        }

        info_print("Mode: Offline T");
        printf("CA hostname: %s, CA port: %s, n: %s, w file: %s\n", h_value, p_value, n_value, w_value);

        mode = MODE_OFFLINE_T;

    } else if (strcmp(m_value, "offline_ca") == 0) {
        if (b_flag != 1 || n_flag != 1) {
            error_print("Missing options");
            show_help();
            return 1;
        }

        info_print("Mode: Offline CA");
        printf("Listening port: %s, n: %s\n", b_value, n_value);

        mode = MODE_OFFLINE_CA;

    } else if (strcmp(m_value, "online_u") == 0) {
        if (h_flag != 1 || p_flag != 1 || i_flag != 1 || q_flag != 1 || n_flag != 1 || s_flag != 1) {
            error_print("Missing options");
            show_help();
            return 1;
        }

        info_print("Mode: Online U");
        printf("CA hostname: %s, CA port: %s, T hostname: %s, T port: %s, n: %s, SNPs file: %s\n", h_value, p_value,
               i_value, q_value, n_value, s_value);

        mode = MODE_ONLINE_U;

    } else if (strcmp(m_value, "online_t") == 0) {
        if (x_flag != 1) {
            x_value = X_FILE;
            x_flag = 1;
        }

        if (c_flag != 1) {
            c_value = CTS_FILE;
            c_flag = 1;
        }

        if (b_flag != 1 || n_flag != 1 || x_flag != 1 || c_flag != 1) {
            error_print("Missing options");
            show_help();
            return 1;
        }

        info_print("Mode: Online T");
        printf("Listening port: %s, n: %s, x file: %s, cts file: %s\n", b_value, n_value, x_value, c_value);

        mode = MODE_ONLINE_T;

    } else if (strcmp(m_value, "online_ca") == 0) {
        if (d_flag != 1) {
            d_value = D_FILE;
            d_flag = 1;
        }

        if (b_flag != 1 || n_flag != 1 || d_flag != 1) {
            error_print("Missing options");
            show_help();
            return 1;
        }

        info_print("Mode: Online CA");
        printf("Listening port: %s, n: %s, d file: %s\n", b_value, n_value, d_value);

        mode = MODE_ONLINE_CA;

    } else {
        error_print("Mode is invalid");
        show_help();
        return 1;
    }

    if (mode == MODE_OFFLINE_T) {
        struct offline_t_args ota = {0};
        ota.ca_hostname = h_value;
        ota.ca_port = p_value;
        ota.n = n_value;
        ota.w_file = w_value;

        int ret = offline_t_handler(&ota);
        if (ret < 0) {
            error_print("offline_t_handler() failed");
            return 1;
        }
    } else if (mode == MODE_OFFLINE_CA) {
        // create socket
        int sockfd = create_tcp_listening_socket(b_value);
        if (sockfd < 0) {
            error_print("create_tcp_listening_socket() failed");
            return 1;
        }

        // thread
        struct offline_ca_args oca = {0};
        pthread_t offline_ca_thread;
        pthread_barrier_t *offline_ca_thread_barrier = (pthread_barrier_t *) malloc(
                sizeof(pthread_barrier_t));
        if (offline_ca_thread_barrier == NULL) {
            error_print("malloc() for barrier failed");

            close(sockfd);
            return 1;
        }
        if (pthread_barrier_init(offline_ca_thread_barrier, NULL, 2) < 0) {
            error_print("pthread_barrier_init() failed");

            close(sockfd);
            free(offline_ca_thread_barrier);
            return 1;
        }
        oca.barrier = offline_ca_thread_barrier;
        oca.n = n_value;

        info_print("Offline CA now accepting connections");
        while (1) {
            int newfd = accept(sockfd, NULL, NULL);
            if (newfd < 0) {
                error_print("accept() failed");

                continue;
            }

            oca.sockfd = newfd;
            if (pthread_create(&offline_ca_thread, NULL, offline_ca_handler,
                               &oca) != 0) {
                error_print("pthread_create() failed");

                close(newfd);
                continue;
            }

            // must be called to avoid memory leaks
            pthread_detach(offline_ca_thread);

            /*allow pthread_detach() to be called before new thread terminates and
             wait until the thread finishes copying arguments onto its own stack*/
            pthread_barrier_wait(offline_ca_thread_barrier);
        }
    } else if (mode == MODE_ONLINE_U) {
        struct online_u_args oua = {0};
        oua.ca_hostname = h_value;
        oua.ca_port = p_value;
        oua.t_hostname = i_value;
        oua.t_port = q_value;
        oua.n = n_value;
        oua.snps_file = s_value;

        int ret = online_u_handler(&oua);
        if (ret < 0) {
            error_print("online_u_handler() failed");
            return 1;
        }
    } else if (mode == MODE_ONLINE_T) {
        // create socket
        int sockfd = create_tcp_listening_socket(b_value);
        if (sockfd < 0) {
            error_print("create_tcp_listening_socket() failed");
            return 1;
        }

        // thread
        struct online_t_args ota = {0};
        pthread_t online_t_thread;
        pthread_barrier_t *online_t_thread_barrier = (pthread_barrier_t *) malloc(
                sizeof(pthread_barrier_t));
        if (online_t_thread_barrier == NULL) {
            error_print("malloc() for barrier failed");

            close(sockfd);
            return 1;
        }
        if (pthread_barrier_init(online_t_thread_barrier, NULL, 2) < 0) {
            error_print("pthread_barrier_init() failed");

            close(sockfd);
            free(online_t_thread_barrier);
            return 1;
        }
        ota.barrier = online_t_thread_barrier;
        ota.n = n_value;
        ota.x_file = x_value;
        ota.cts_file = c_value;

        info_print("Online T now accepting connections");
        while (1) {
            int newfd = accept(sockfd, NULL, NULL);
            if (newfd < 0) {
                error_print("accept() failed");

                continue;
            }

            ota.sockfd = newfd;
            if (pthread_create(&online_t_thread, NULL, online_t_handler,
                               &ota) != 0) {
                error_print("pthread_create() failed");

                close(newfd);
                continue;
            }

            // must be called to avoid memory leaks
            pthread_detach(online_t_thread);

            /*allow pthread_detach() to be called before new thread terminates and
             wait until the thread finishes copying arguments onto its own stack*/
            pthread_barrier_wait(online_t_thread_barrier);
        }
    } else if (mode == MODE_ONLINE_CA) {
        // create socket
        int sockfd = create_tcp_listening_socket(b_value);
        if (sockfd < 0) {
            error_print("create_tcp_listening_socket() failed");
            return 1;
        }

        // thread
        struct online_ca_args oca = {0};
        pthread_t online_ca_thread;
        pthread_barrier_t *online_ca_thread_barrier = (pthread_barrier_t *) malloc(
                sizeof(pthread_barrier_t));
        if (online_ca_thread_barrier == NULL) {
            error_print("malloc() for barrier failed");

            close(sockfd);
            return 1;
        }
        if (pthread_barrier_init(online_ca_thread_barrier, NULL, 2) < 0) {
            error_print("pthread_barrier_init() failed");

            close(sockfd);
            free(online_ca_thread_barrier);
            return 1;
        }
        oca.barrier = online_ca_thread_barrier;
        oca.n = n_value;
        oca.d_file = d_value;

        info_print("Online CA now accepting connections");
        while (1) {
            int newfd = accept(sockfd, NULL, NULL);
            if (newfd < 0) {
                error_print("accept() failed");

                continue;
            }

            oca.sockfd = newfd;
            if (pthread_create(&online_ca_thread, NULL, online_ca_handler,
                               &oca) != 0) {
                error_print("pthread_create() failed");

                close(newfd);
                continue;
            }

            // must be called to avoid memory leaks
            pthread_detach(online_ca_thread);

            /*allow pthread_detach() to be called before new thread terminates and
             wait until the thread finishes copying arguments onto its own stack*/
            pthread_barrier_wait(online_ca_thread_barrier);
        }
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
    // exit success
    ////////////////////////////////////////////////
    info_print("Program exiting successfully");
    return 0;
}
