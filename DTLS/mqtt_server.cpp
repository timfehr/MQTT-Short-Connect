#pragma clang diagnostic push
#pragma ide diagnostic ignored "hicpp-signed-bitwise"

#include <iostream>
#include <sys/socket.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h> // for read, write...
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include "Classes/Connect_Packet.h"
#include "Classes/Connect_Ack.h"
#include "Classes/Subscribe_Request.h"
#include "Classes/Subscribe_Ack.h"
#include "Classes/Short_Connect.h"
#include "Classes/Short_Ack.h"

#define SERV_UDP_PORT 8883
#define COOKIE_SECRET_LENGTH 16

using namespace std;

void *s_server_session_id_context;
char *psk_identity_hint = NULL;
uint8_t buffer[1024] = {0};
SSL *ssl = nullptr;
ssize_t valread;
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int cookie_initialized = 0;
struct sockaddr_in serv_addr;
struct sockaddr_in client_addr;

int create_socket();

void init_openssl();

SSL_CTX *create_context();

void configure_context(SSL_CTX *);

void cleanup_openssl();

void debug_output_connect_header(Connect_Packet *tmp);

void debug_output_short_connect(Short_Connect *sc);

int check_short_connect(const uint8_t *buffer);

void short_connect(bool early);

void normal_connect(bool early);

int main() {
    int my_socket;
    SSL_CTX *ctx = nullptr;
    char *ip;
    int port;
    string nachricht;
    int ret;
    struct timeval timeout;

    //Init OpenSSL
    init_openssl();
    ctx = create_context();
    configure_context(ctx);

    //Create socket with options
    my_socket = create_socket();

    cout << "Ready for connection..." << endl;

    //Endlosschleife um Verbindungen anzunehmen
    while (true) {
        const int on = 1;
        BIO *bio = BIO_new_dgram(my_socket, BIO_NOCLOSE);

        /* Set and activate timeouts */
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        /* Create context */
        ssl = SSL_new(ctx);
        SSL_set_bio(ssl, bio, bio);

        /* Enable cookie exchange */
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

        /* Wait for incoming connections */
        while (!DTLSv1_listen(ssl, (BIO_ADDR *) &client_addr));

        close(my_socket);

        OPENSSL_assert(client_addr.sin_family == serv_addr.sin_family);
        /* Handle client connection */
        int client_fd = socket(client_addr.sin_family, SOCK_DGRAM, 0);
        if (client_fd == -1) {
            perror("ERROR: Cannot create client socket");
            exit(-1);
        }

        setsockopt(client_fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
        setsockopt(client_fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));

        if(::bind(client_fd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in)) == -1) {
            perror("ERROR: Cannot bind local address");
            //exit(-1);
        }

        if(connect(client_fd, (struct sockaddr *)&client_addr, sizeof(struct sockaddr_in)) < 0) {
            perror("ERROR: Cannot connect");
            exit(-1);
        }

        /* Set new fd and set BIO to connected */
        BIO *cbio = SSL_get_rbio(ssl);
        BIO_set_fd(cbio, client_fd, BIO_NOCLOSE);
        BIO_ctrl(cbio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr);
        BIO_ctrl(cbio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        do { ret = SSL_accept(ssl); }
        while (ret == 0);
        if (ret < 0) {
            perror("SSL_accept error: ");
            exit(-1);
        }

        ip = inet_ntoa(client_addr.sin_addr);
        port = ntohs(client_addr.sin_port);

        //Debug output
        cout << "Successful UDP with TLS (DTLS) connection!" << endl;
        cout << "Client IP: " << ip << ":" << port << endl;

        //Wait for client to send data
        do {
            valread = SSL_read(ssl, buffer, 1024);
        } while (valread < 0);


        int validate = check_short_connect(buffer);

        switch (validate) {
            case 0: {
                cout << "Short Connect bekommen..." << endl;

                short_connect(false);

                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(client_fd);

                break;
            }

            case 1: {
                cout << "Normales Connect bekommen..." << endl;

                normal_connect(false);

                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(client_fd);

                break;
            }

            case 2: {
                cout << "ERROR: Connect expected but it isn't" << endl;
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(client_fd);
                break;
            }

            default:
                break;
        }
    }

    SSL_CTX_free(ctx);
    cleanup_openssl();
}

void debug_output_connect_header(Connect_Packet *tmp) {
    cout << "Protokoll: " << tmp->getProtName() << endl;
    cout << "ClientID: " << tmp->getClientid() << endl;
}

void debug_output_short_connect(Short_Connect *sc) {
    cout << "Protokoll: " << sc->getCon().getProtName() << endl;
    cout << "ClientID: " << sc->getCon().getClientid() << endl;
    cout << "Topic: " << sc->getSubReq().getTopic() << endl;
    cout << "QoS: " << (int) sc->getSubReq().getSubOptions() << endl;
}

int check_short_connect(const uint8_t *buffer) {
    if (buffer[0] == 0x10 && buffer[9] == 0x03) {
        return 0;
    } else if (buffer[0] == 0x10) {
        return 1;
    } else {
        return 2;
    }
}

int create_socket() {
    int my_socket;

    if ((my_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("ERROR: failed to create TCP-Socket");
        exit(-1);
    }

    //Set socket options
    int optvar = 1;
    if (setsockopt(my_socket, SOL_SOCKET, SO_REUSEADDR, &optvar, sizeof(optvar))) {
        perror("Option REUSEADDR could not be set");
        exit(-1);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(SERV_UDP_PORT);

    //Bind socket to ip and port
    if (::bind(my_socket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) == -1) {
        perror("ERROR: Cannot bind local address");
        exit(-1);
    }

    return my_socket;
}

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, resultlength;
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in6 s6;
        struct sockaddr_in s4;
    } peer;

    /* Initialize a random secret */
    if (!cookie_initialized) {
        if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH)) {
            printf("error setting random cookie secret\n");
            return 0;
        }
        cookie_initialized = 1;
    }

    /* Read peer information */
    (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    /* Create buffer with peer's address and port */
    length = 0;
    switch (peer.ss.ss_family) {
        case AF_INET:
            length += sizeof(struct in_addr);
            break;
        case AF_INET6:
            length += sizeof(struct in6_addr);
            break;
        default:
            OPENSSL_assert(0);
            break;
    }
    length += sizeof(in_port_t);
    buffer = (unsigned char *) OPENSSL_malloc(length);

    if (buffer == NULL) {
        printf("out of memory\n");
        return 0;
    }

    switch (peer.ss.ss_family) {
        case AF_INET:
            memcpy(buffer,
                   &peer.s4.sin_port,
                   sizeof(in_port_t));
            memcpy(buffer + sizeof(peer.s4.sin_port),
                   &peer.s4.sin_addr,
                   sizeof(struct in_addr));
            break;
        case AF_INET6:
            memcpy(buffer,
                   &peer.s6.sin6_port,
                   sizeof(in_port_t));
            memcpy(buffer + sizeof(in_port_t),
                   &peer.s6.sin6_addr,
                   sizeof(struct in6_addr));
            break;
        default:
            OPENSSL_assert(0);
            break;
    }

    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), (const void *) cookie_secret, COOKIE_SECRET_LENGTH,
         (const unsigned char *) buffer, length, result, &resultlength);
    OPENSSL_free(buffer);

    memcpy(cookie, result, resultlength);
    *cookie_len = resultlength;

    return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, resultlength;
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in6 s6;
        struct sockaddr_in s4;
    } peer;

    /* If secret isn't initialized yet, the cookie can't be valid */
    if (!cookie_initialized)
        return 0;

    /* Read peer information */
    (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    /* Create buffer with peer's address and port */
    length = 0;
    switch (peer.ss.ss_family) {
        case AF_INET:
            length += sizeof(struct in_addr);
            break;
        case AF_INET6:
            length += sizeof(struct in6_addr);
            break;
        default:
            OPENSSL_assert(0);
            break;
    }
    length += sizeof(in_port_t);
    buffer = (unsigned char *) OPENSSL_malloc(length);

    if (buffer == NULL) {
        printf("out of memory\n");
        return 0;
    }

    switch (peer.ss.ss_family) {
        case AF_INET:
            memcpy(buffer,
                   &peer.s4.sin_port,
                   sizeof(in_port_t));
            memcpy(buffer + sizeof(in_port_t),
                   &peer.s4.sin_addr,
                   sizeof(struct in_addr));
            break;
        case AF_INET6:
            memcpy(buffer,
                   &peer.s6.sin6_port,
                   sizeof(in_port_t));
            memcpy(buffer + sizeof(in_port_t),
                   &peer.s6.sin6_addr,
                   sizeof(struct in6_addr));
            break;
        default:
            OPENSSL_assert(0);
            break;
    }

    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), (const void *) cookie_secret, COOKIE_SECRET_LENGTH,
         (const unsigned char *) buffer, length, result, &resultlength);
    OPENSSL_free(buffer);

    if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
        return 1;

    return 0;
}

int verify_callback (int ok, X509_STORE_CTX *ctx) {
    /* This function should ask the user
     * if he trusts the received certificate.
     * Here we always trust.
     */
    return 1;
}

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = DTLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_read_ahead(ctx, 1);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, verify_callback);
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie);
}

void cleanup_openssl() {
    EVP_cleanup();
}

void short_connect(bool early) {
    auto *short_con = new Short_Connect(buffer);
    auto *short_ack = new Short_Ack();

    short_ack->setMsgId1(short_con->getSubReq().getMsgId_1());
    short_ack->setMsgId2(short_con->getSubReq().getMsgId_2());
    short_ack->getConAck().setReasonCode(short_con->getSubReq().getSubOptions());
    short_ack->calc_msg_length();
    string sa = short_ack->build_packet();
    char ack[sa.size()];
    memcpy(ack, sa.c_str(), sizeof(ack));

    size_t writtenbytes;

    if (early) {
        while (!SSL_write_early_data(ssl, ack, sizeof(ack), &writtenbytes)) {
            switch (SSL_get_error(ssl, 0)) {
                case SSL_ERROR_WANT_WRITE:
                case SSL_ERROR_WANT_ASYNC:
                case SSL_ERROR_WANT_READ:
                    //Just keep trying - busy waiting
                    continue;
                default:
                    cout << "Error writing early data" << endl;
            }
        }
    } else {
        //Send Short Ack packet
        if (SSL_write(ssl, ack, sizeof(ack)) < 0) {
            perror("ERROR: Could not send connect packet");
        }
    }
}

void normal_connect(bool early) {
    //Set all data and validate
    auto *connect = new Connect_Packet(buffer);

    if (connect->validate()) {
        //Send Connect Ack
        auto *con_ack = new Connect_Ack();

        con_ack->calc_msg_length();
        string ack = con_ack->build_packet();
        char con[ack.size()];
        memcpy(con, ack.c_str(), sizeof(con));

        size_t writtenbytes;

        if (early) {
            while (!SSL_write_early_data(ssl, con, sizeof(con), &writtenbytes)) {
                switch (SSL_get_error(ssl, 0)) {
                    case SSL_ERROR_WANT_WRITE:
                    case SSL_ERROR_WANT_ASYNC:
                    case SSL_ERROR_WANT_READ:
                        //Just keep trying - busy waiting
                        continue;
                    default:
                        cout << "Error writing early data" << endl;
                }
            }
        } else {
            //Send Connect packet
            if (SSL_write(ssl, con, sizeof(con)) < 0) {
                perror("ERROR: Could not send connect packet");
            }
        }

        //Wait for response
        do {
            valread = SSL_read(ssl, buffer, 1024);
        } while (valread < 0);

        auto *sub_req = new Subscribe_Request(buffer);

        if (sub_req->validate()) {
            cout << "Valides Subscribe Request mit Topic: " << sub_req->getTopic() << endl;
            cout << "Sub Options: " << (int) sub_req->getSubOptions() << endl;

            auto *sub_ack = new Subscribe_Ack();
            sub_ack->setMsgId1(sub_req->getMsgId_1());
            sub_ack->setMsgId2(sub_req->getMsgId_2());
            sub_ack->setReasonCode(sub_req->getSubOptions());

            sub_ack->calc_msg_length();
            string sub_ack_str = sub_ack->build_packet();
            char sas[sub_ack_str.size()];
            memcpy(sas, sub_ack_str.c_str(), sizeof(sas));

            //Send Subscribe Ack packet
            if (SSL_write(ssl, sas, sizeof(sas)) < 0) {
                perror("ERROR: Could not send connect packet");
            }
        } else {
            cout << "Kein valides Sub_Req mit Topic: " << sub_req->getTopic() << endl;
            cout << "Sub Options: " << (int) sub_req->getSubOptions() << endl;
        }
    }
}