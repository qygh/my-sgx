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
#include <stdio.h>
#include <cstring>

#include "utils.h"
#include "app.h"
#include "wallet.h"
#include "enclave.h"


/**
 * @brief      Prints an info message. 
 *
 */
void info_print(const char *str) {
    printf("[INFO] %s\n", str);
}


/**
 * @brief      Prints a warning message.
 *
 */
void warning_print(const char *str) {
    printf("[WARNING] %s\n", str);
}


/**
 * @brief      Prints an error message. 
 *
 */
void error_print(const char *str) {
    printf("[ERROR] %s\n", str);
}


/**
 * @brief      Prints the wallet's content.
 *
 */
void print_wallet(const wallet_t *wallet) {
    printf("\n-----------------------------------------\n\n");
    printf("%s v%s\n", APP_NAME, VERSION);
    printf("Simple password wallet based on Intel SGX.\n\n");
    printf("Number of items: %lu\n\n", wallet->size);
    for (int i = 0; i < wallet->size; ++i) {
        printf("#%d -- %s\n", i, wallet->items[i].title);
        printf("[username:] %s\n", wallet->items[i].username);
        printf("[password:] %s\n", wallet->items[i].password);
        printf("\n");
    }
    printf("\n------------------------------------------\n\n");
}


/**
 * @brief      Prints an error message correspondig to the
 *             error code.
 *
 */
int is_error(int error_code) {
    char err_message[100];

    // check error case
    switch (error_code) {
        case RET_SUCCESS:
            return 0;

        case ERR_PASSWORD_OUT_OF_RANGE:
            sprintf(err_message, "Password should be at least 8 characters long and at most %d.", MAX_ITEM_SIZE);
            break;

        case ERR_WALLET_ALREADY_EXISTS:
            sprintf(err_message, "Wallet already exists: delete file '%s' first.", WALLET_FILE);
            break;

        case ERR_CANNOT_SAVE_WALLET:
            strcpy(err_message, "Coud not save wallet.");
            break;

        case ERR_CANNOT_LOAD_WALLET:
            strcpy(err_message, "Coud not load wallet.");
            break;

        case ERR_WRONG_MASTER_PASSWORD:
            strcpy(err_message, "Wrong master password.");
            break;

        case ERR_WALLET_FULL:
            sprintf(err_message, "Wallet full (maximum number of item: %d).", MAX_ITEMS);
            break;

        case ERR_ITEM_DOES_NOT_EXIST:
            strcpy(err_message, "Item does not exist.");
            break;

        case ERR_ITEM_TOO_LONG:
            sprintf(err_message, "Item too longth (maximum size: %d).", MAX_ITEM_SIZE);
            break;

        case ERR_FAIL_SEAL:
            sprintf(err_message, "Fail to seal wallet.");
            break;

        case ERR_FAIL_UNSEAL:
            sprintf(err_message, "Fail to unseal wallet.");
            break;

        default:
            sprintf(err_message, "Unknown error.");
    }

    // print error message
    error_print(err_message);
    return 1;
}


/**
 * @brief      Prints help & usage. 
 *
 */
/*void show_help() {
    const char *command = "[-h Show this screen] [-v Show version] [-t Run tests] " \
        "[-n master-password] [-p master-password -c new-master-password]" \
        "[-p master-password -a -x items_title -y items_username -z toitems_password]" \
        "[-p master-password -r items_index]";
    printf("\nusage: %s %s\n\n", APP_NAME, command);
    printf("more information: https://github.com/asonnino/sgx-wallet\n\n");
}*/
void show_help() {
    printf("\n\nMY-SGX\n\n");
    printf("Usage:\n");

    printf("\tTest mode:\n");
    printf("\t\"-m test\" to set mode\n\n");

    printf("\tOffline T mode:\n");
    printf("\t\"-m offline_t\" to set mode\n");
    printf("\t\"-h hostname\" to specify CA server hostname\n");
    printf("\t\"-p port\" to specify CA server port\n");
    printf("\t\"-n number\" to specify the number of SNPs/weights\n");
    printf("\t\"-w weights\" to specify the weights file\n\n");

    printf("\tOffline CA mode:\n");
    printf("\t\"-m offline_ca\" to set mode\n");
    printf("\t\"-b port\" to specify the listening port\n");
    printf("\t\"-n number\" to specify the number of SNPs/weights\n\n");

    printf("\tOnline U mode:\n");
    printf("\t\"-m online_u\" to set mode\n");
    printf("\t\"-h hostname\" to specify CA server hostname\n");
    printf("\t\"-p port\" to specify CA server port\n");
    printf("\t\"-i hostname\" to specify T server hostname\n");
    printf("\t\"-q port\" to specify T server port\n");
    printf("\t\"-n number\" to specify the number of SNPs/weights\n");
    printf("\t\"-s snps\" to specify the SNPs file\n\n");

    printf("\tOnline T mode:\n");
    printf("\t\"-m online_t\" to set mode\n");
    printf("\t\"-b port\" to specify the listening port\n");
    printf("\t\"-n number\" to specify the number of SNPs/weights\n");
    printf("\t\"-x x\" to specify the x file\n");
    printf("\t\"-c cts\" to specify the cts file\n\n");

    printf("\tOnline CA mode:\n");
    printf("\t\"-m online_ca\" to set mode\n");
    printf("\t\"-b port\" to specify the listening port\n");
    printf("\t\"-n number\" to specify the number of SNPs/weights\n");
    printf("\t\"-d d\" to specify the d file\n\n");
}


/**
 * @brief      Prints the build version. 
 *
 */
void show_version() {
    printf("v%s\n", VERSION);
}

ssize_t load_file(const char *filename, uint8_t *buffer, size_t length) {
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    if (file.fail()) {
        return -1;
    }

    file.read((char *) buffer, length);
    if (file.fail()) {
        return -1;
    }

    file.close();
    return 0;
}

ssize_t save_file(const char *filename, const uint8_t *buffer, size_t length) {
    std::ofstream file(filename, std::ios::out | std::ios::binary);
    if (file.fail()) {
        return -1;
    }

    file.write((const char *) buffer, length);
    if (file.fail()) {
        return -1;
    }

    file.close();
    return 0;
}

int create_tcp_client_socket(const char *hostname, const char *port) {
    struct addrinfo hints = {0};
    struct addrinfo *res = NULL;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int ret = getaddrinfo(hostname, port, &hints, &res);
    if (ret != 0) {
        fprintf(stderr, "create_tcp_client_socket: getaddrinfo(): %s\n", gai_strerror(ret));
        return -1;
    }

    // create socket
    int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd == -1) {
        fprintf(stderr, "create_tcp_client_socket: socket(): %s\n", strerror(errno));

        freeaddrinfo(res);
        return -1;
    }

    // connect socket
    if (connect(sockfd, res->ai_addr, res->ai_addrlen) != 0) {
        fprintf(stderr, "create_tcp_client_socket: connect(): %s\n", strerror(errno));

        close(sockfd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    return sockfd;
}

int create_tcp_listening_socket(const char *port) {
    int sockfd = socket(PF_INET6, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("create_tcp_listening_socket(): socket() error");
        return -1;
    }

    // work with both IPv4 and IPv6
    int zero = 0;
    int soret = setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &zero,
                           sizeof(zero));
    if (soret < 0) {
        perror("create_tcp_listening_socket(): setsockopt() error");
        fprintf(stderr,
                "create_tcp_listening_socket(): Server might not work with IPv4 clients\n");
    }

    // reuse port
    int one = 1;
    soret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (soret < 0) {
        perror("create_tcp_listening_socket(): setsockopt() error");
    }

    // bind
    struct sockaddr_in6 sockaddr = {0};
    sockaddr.sin6_addr = in6addr_any;
    sockaddr.sin6_family = AF_INET6;
    sockaddr.sin6_port = htons((uint16_t) strtol(port, NULL, 10));
    int ret = bind(sockfd, (struct sockaddr *) &sockaddr, sizeof(sockaddr));
    if (ret < 0) {
        perror("create_tcp_listening_socket(): bind() error");
        close(sockfd);
        return -1;
    }

    // listen
    ret = listen(sockfd, 20);
    if (ret < 0) {
        perror("create_tcp_listening_socket(): listen() error");
        close(sockfd);
        return -1;
    }

    return sockfd;
}


ssize_t tcp_read(int fd, uint8_t *buf, size_t count) {
    if (count <= 0) {
        return count;
    }

    size_t bytes_read = 0;
    size_t bytes_left = count;

    ssize_t ret;
    while (bytes_left != 0) {
        ret = read(fd, buf + bytes_read, bytes_left);

        if (ret < 0) {
            perror("read()");
            return ret;
        } else if (ret == 0) {
            return bytes_read;
        } else {
            bytes_read += ret;
            bytes_left -= ret;
        }
    }

    return bytes_read;
}


ssize_t tcp_write(int fd, const uint8_t *buf, size_t count) {
    if (count <= 0) {
        return count;
    }

    size_t bytes_written = 0;
    size_t bytes_left = count;

    ssize_t ret;
    while (bytes_left != 0) {
        ret = write(fd, buf + bytes_written, bytes_left);

        if (ret < 0) {
            perror("write()");
            return ret;
        } else if (ret == 0) {
            return bytes_written;
        } else {
            bytes_written += ret;
            bytes_left -= ret;
        }
    }

    return bytes_written;
}