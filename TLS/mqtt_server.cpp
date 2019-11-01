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
#include <openssl/err.h>
#include <openssl/e_os2.h>
#include "Classes/Connect_Packet.h"
#include "Classes/Connect_Ack.h"
#include "Classes/Subscribe_Request.h"
#include "Classes/Subscribe_Ack.h"
#include "Classes/Short_Connect.h"
#include "Classes/Short_Ack.h"

#define SERV_TCP_PORT 8883

using namespace std;

void *s_server_session_id_context;
char *psk_identity_hint = NULL;
uint8_t buffer[1024] = {0};
SSL *ssl = nullptr;
ssize_t valread;

int create_socket();

void init_openssl();

SSL_CTX *create_context();

void configure_context(SSL_CTX *);

void cleanup_openssl();

void debug_output_connect_header(Connect_Packet *tmp);

void debug_output_short_connect(Short_Connect *sc);

int check_short_connect(const uint8_t *buffer);

void short_connect (bool early);

void normal_connect (bool early);

int main() {
    int my_socket, clilen, childpid, newsocket;
    SSL_CTX *ctx = nullptr;
    char *ip;
    int port;
    
    string nachrichtt;

    //Init OpenSSL
    init_openssl();
    ctx = create_context();
    configure_context(ctx);

    //Create socket with options
    my_socket = create_socket();

    cout << "Ready for connections..." << endl;

    struct sockaddr_in client_addr{};
    clilen = sizeof(client_addr);

    //Endlosschleife um Verbindungen anzunehmen
    while (true) {
        //Verbindung annehmen -> blockiert bis Verbindung kommt
        newsocket = accept(my_socket, (struct sockaddr *) &client_addr, (socklen_t *) &clilen);
        if (newsocket > 0) {
            ip = inet_ntoa(client_addr.sin_addr);
            port = ntohs(client_addr.sin_port);

        } else {
            sleep(1);
            continue;
        }
        //Do the SSL connection establishment
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, newsocket);

        int early_data_error = 1;
        int edret = SSL_READ_EARLY_DATA_ERROR;
        size_t readbytes;

        while (edret != SSL_READ_EARLY_DATA_FINISH) {
            for (;;) {
                edret = SSL_read_early_data(ssl, buffer, 1024, &readbytes);
                if (edret != SSL_READ_EARLY_DATA_ERROR) {
                    break;
                }

                switch (SSL_get_error(ssl, 0)) {
                    case SSL_ERROR_WANT_WRITE:
                    case SSL_ERROR_WANT_ASYNC:
                    case SSL_ERROR_WANT_READ:
                        // Just keep trying - busy waiting
                        continue;
                    default:
                        cout << "Error reading early data" << endl;
                }
            }

            if (check_short_connect(buffer) == 0) {
                short_connect(true);
                break;
            } else if (check_short_connect(buffer) == 1){
                normal_connect (true);
                break;
            }

            if (readbytes > 0) {
                if (early_data_error) {
                    cout << "Early Data received!" << endl;
                    early_data_error = 0;
                }
            }
        }

        //Debug output
        cout << "Successful TCP with TLS connection!" << endl;
        cout << "Client IP: " << ip << ":" << port << endl;

        if (early_data_error) {
            if (SSL_get_early_data_status(ssl) == SSL_EARLY_DATA_NOT_SENT) {
                cout << "No early data received" << endl;
            } else {
                cout << "Early data was rejected" << endl;
            }

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
                    close(newsocket);

                    break;
                }

                case 1: {
                    cout << "Normales Connect bekommen..." << endl;

                    normal_connect(false);

                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    close(newsocket);

                    break;
                }

                case 2: {
                    cout << "ERROR: Connect expected but it isn't" << endl;
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    close(newsocket);
                    break;
                }

                default:
                    break;
            }
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
    struct sockaddr_in serv_addr{};

    if ((my_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        perror("ERROR: failed to create TCP-Socket");
        exit(-1);
    }

    //Set socket options
    int optvar = 1;
    if (setsockopt(my_socket, SOL_SOCKET, SO_REUSEADDR, &optvar, sizeof(optvar))) {
        perror("Option REUSEADDR could not be set");
        exit(-1);
    }

    int flags = 1;
    if (setsockopt(my_socket, IPPROTO_TCP, TCP_NODELAY, (void *) &flags, sizeof(flags))) {
        perror("ERROR: Could not set TCP_NODELAY option");
    }

    int flag = 5;
    if (setsockopt(my_socket, IPPROTO_TCP, TCP_FASTOPEN, (void *) &flag, sizeof(flag))) {
        perror("ERROR: Could not set TCP_FASTOPEN_CONNECT option");
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(SERV_TCP_PORT);

    //Bind socket to ip and port
    if (::bind(my_socket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) == -1) {
        perror("ERROR: Cannot bind local address");
        exit(-1);
    }

    //Set socket to listen
    if (listen(my_socket, 5) < 0) {
        perror("ERROR: Cannot listen to socket");
        exit(-1);
    }

    return my_socket;
}

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

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

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);

    if (!SSL_CTX_use_psk_identity_hint(ctx, psk_identity_hint)) {
        cout << "error setting PSK identity hint to context" << endl;
    }

    if (!SSL_CTX_set_session_id_context(ctx, reinterpret_cast<const unsigned char *>(&s_server_session_id_context),
                                        sizeof(s_server_session_id_context))) {
        cout << "error setting session id context" << endl;
    }

    SSL_CTX_set_max_early_data(ctx, 1024);
    SSL_CTX_set_recv_max_early_data(ctx, 1024);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void cleanup_openssl() {
    EVP_cleanup();
}

void short_connect (bool early) {
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

void normal_connect (bool early) {
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