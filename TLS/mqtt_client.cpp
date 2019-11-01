#include <iostream>
#include <sys/socket.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <fstream>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "Classes/Connect_Packet.h"
#include "Classes/Connect_Ack.h"
#include "Classes/Subscribe_Request.h"
#include "Classes/Subscribe_Ack.h"
#include "Classes/Short_Connect.h"
#include "Classes/Short_Ack.h"

using namespace std;

const char *filename = "config.env";
string ip;
int port;
string clientid;
string topic;
int qos;
bool use_early_data = true;

static BIO *bio_keylog = nullptr;
static BIO *session_log = nullptr;
static BIO *session_key = nullptr;

void parse_config();
int create_socket();
void init_openssl();
SSL_CTX *create_context();
void configure_context(SSL_CTX *);
void cleanup_openssl();
static void keylog_callback(const SSL *ssl, const char *line);
static int new_session_cb(SSL *ssl, SSL_SESSION *session);

int main(int argc, char *argv[]) {
    auto *connect = new Connect_Packet();
    auto *sub_req = new Subscribe_Request();
    int my_socket;
    SSL_CTX *ctx = nullptr;
    SSL *ssl = nullptr;
    SSL_SESSION *session = nullptr;
    string mqtt_header;
    string mqtt_sub_req;
    string sc_input;
    uint8_t buffer[1024] = {0};
    ssize_t valread;
    char input;

    //Read config
    parse_config();

    //Init OpenSSL and create SSL context
    init_openssl();
    ctx = create_context();
    configure_context(ctx);

    //Ask User if he/she wants to use short connect
    cout << "Short Connect verwenden? ";
    cin >> input;

    //Set socket options and create socket
    struct sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);  // ggfs aendern! Port des Servers
    server_addr.sin_addr.s_addr = inet_addr(ip.c_str()); // ggfs Aendern! IP Adresse des Servers, z.B. "localhost"
    my_socket = create_socket();

    //Set TCP_NODELAY option
    int flags = 1;
    if (setsockopt(my_socket, IPPROTO_TCP, TCP_NODELAY, (void *) &flags, sizeof(flags))) {
        perror("ERROR: Could not set TCP_NODELAY option");
    }

    int flag = 1;
    if (setsockopt(my_socket, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, (void *) &flag, sizeof(flag))) {
        perror("ERROR: Could not set TCP_FASTOPEN_CONNECT option");
    }

    //TCP connect to server
    if (::connect(my_socket, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("ERROR: TCP could not Connect");
        exit(-1);
    }

    //Set Options and Sessions
    ssl = SSL_new(ctx);

    session_log = BIO_new_file("session.log", "r");
    if (session_log == NULL) {
        cout << "ERROR: Reading Session!" << endl;
    }

    session = PEM_read_bio_SSL_SESSION(session_log, NULL, 0, NULL);
    BIO_free(session_log);
    if (session == NULL) {
        cout << "ERROR: Cannot open session file!" << endl;
    }

    if (!SSL_set_session(ssl, session)) {
        cout << "ERROR: Cannot set session!" << endl;
    }

    //SSL_SESSION_free(session);

    SSL_set_fd(ssl, my_socket);

    switch (input) {
        case 'y': {
            cout << endl << "Short Connect wird vernwendet..." << endl;

            //Generate new Short Connect instance
            auto *short_con = new Short_Connect();

            //Set all variables
            short_con->getCon().setClientid(clientid);
            short_con->getCon().calc_clientid_length();
            short_con->getSubReq().setTopic(topic);
            short_con->getSubReq().setSubOptions(qos);
            short_con->getSubReq().calc_topic_length();
            short_con->calc_msg_length();

            //Build packet to send
            string mqtt_short = short_con->build_packet();
            char sc[mqtt_short.size()];
            memcpy(sc, mqtt_short.c_str(), sizeof(sc));

            if (use_early_data && (SSL_get0_session(ssl) != NULL) && (SSL_SESSION_get_max_early_data(SSL_get0_session(ssl)) > 0)) {
                cout << "Wir benutzen jetzt early data" << endl;

                size_t writtenbytes;

                while (!SSL_write_early_data(ssl, sc, sizeof(sc), &writtenbytes)) {
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

                //cout << "Bytes written: " << writtenbytes << endl;

                //TLS connect
                if (SSL_connect(ssl) <= 0) {
                    fprintf(stderr, "SSL_connect failed\n");
                    exit(EXIT_FAILURE);
                }
            } else {
                /*//TLS connect
                if (SSL_connect(ssl) <= 0) {
                    fprintf(stderr, "SSL_connect failed\n");
                    exit(EXIT_FAILURE);
                }

                //Send Short Connect packet
                if (SSL_write(ssl, sc, sizeof(sc)) < 0) {
                    perror("ERROR: Could not send connect packet");
                }*/
            }

            if (SSL_get_early_data_status(ssl) == SSL_EARLY_DATA_NOT_SENT || SSL_get_early_data_status(ssl) == SSL_EARLY_DATA_REJECTED) {
                cout << "Early not send" << endl;

                //TLS connect
                if (SSL_connect(ssl) <= 0) {
                    fprintf(stderr, "SSL_connect failed\n");
                    exit(EXIT_FAILURE);
                }

                //Send Short Connect packet
                if (SSL_write(ssl, sc, sizeof(sc)) < 0) {
                    perror("ERROR: Could not send connect packet");
                }
            }

            if (SSL_get_early_data_status(ssl) == SSL_EARLY_DATA_ACCEPTED) {
                cout << "Early accepted" << endl;
            }


            if (SSL_session_reused(ssl)) {
                cout << "REUSED SESSION" <<
                endl;
            } else {
                cout << "NEW SESSION" << endl;
            }

            //Wait for Short Ack
            do {
                valread = SSL_read(ssl, buffer, 1024);
            } while (valread < 0);

            //Set the incoming data to the short connect object
            auto *short_ack = new Short_Ack(buffer);

            //Validate
            if (short_ack->validate(short_con)) {
                cout << "Short Connect erfolgreich!!!" << endl;
            } else {
                cout << "Short Connect NICHT erflogreich!!!" << endl;
            }

            break;
        }

        case 'n': {
            //Set all variables
            connect->setClientid(clientid);
            connect->calc_clientid_length();
            connect->calc_msg_length();

            //Build packet to send
            mqtt_header = connect->build_packet();
            char con[mqtt_header.size()];
            memcpy(con, mqtt_header.c_str(), sizeof(con));

            if (use_early_data && (SSL_get0_session(ssl) != NULL) && (SSL_SESSION_get_max_early_data(SSL_get0_session(ssl)) > 0)) {
                cout << "Wir benutzen jetzt early data" << endl;

                size_t writtenbytes;

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

                cout << "Bytes written: " << writtenbytes << endl;

                //TLS connect
                if (SSL_connect(ssl) <= 0) {
                    fprintf(stderr, "SSL_connect failed\n");
                    exit(EXIT_FAILURE);
                }
            } else {
                /*//TLS connect
                if (SSL_connect(ssl) <= 0) {
                    fprintf(stderr, "SSL_connect failed\n");
                    exit(EXIT_FAILURE);
                }

                //Send Short Connect packet
                if (SSL_write(ssl, con, sizeof(con)) < 0) {
                    perror("ERROR: Could not send connect packet");
                }*/
            }

            if (SSL_get_early_data_status(ssl) == SSL_EARLY_DATA_NOT_SENT || SSL_get_early_data_status(ssl) == SSL_EARLY_DATA_REJECTED) {
                cout << "Early not send" << endl;

                if (SSL_connect(ssl) <= 0) {
                    fprintf(stderr, "SSL_connect failed\n");
                    exit(EXIT_FAILURE);
                }

                //Send Short Connect packet
                if (SSL_write(ssl, con, sizeof(con)) < 0) {
                    perror("ERROR: Could not send connect packet");
                }
            }

            if (SSL_get_early_data_status(ssl) == SSL_EARLY_DATA_ACCEPTED) {
                cout << "Early accepted" << endl;
            }

            if (SSL_session_reused(ssl)) {
                cout << "REUSED SESSION" <<
                     endl;
            } else {
                cout << "NEW SESSION" << endl;
            }

            //Wait for Connect response
            do {
                valread = SSL_read(ssl, buffer, 1024);
            } while (valread < 0);

            //Set the incoming data to the packet
            auto *conn_ack = new Connect_Ack(buffer);

            if (conn_ack->validate()) {
                //Set Subscrive Requests variables
                sub_req->setTopic(topic);
                sub_req->setSubOptions(qos);
                sub_req->calc_topic_length();
                sub_req->calc_msg_length();

                //build packet to send
                mqtt_sub_req = sub_req->build_packet();
                char req[mqtt_sub_req.size()];
                memcpy(req, mqtt_sub_req.c_str(), sizeof(req));

                if (SSL_write(ssl, req, sizeof(con)) < 0) {
                    perror("ERROR: Could not send connect packet");
                }

                //Wait for Subscribe Ack
                do {
                    valread = SSL_read(ssl, buffer, 1024);
                } while (valread < 0);

                //Set the incoming data
                auto *sub_ack = new Subscribe_Ack(buffer);

                //Validate if Subscribe Ack
                if (sub_ack->validate()) {
                    //Validate the same message identifier and the same QoS
                    if ((sub_ack->getMsgId1() == sub_req->getMsgId_1()) &&
                        (sub_ack->getMsgId2() == sub_req->getMsgId_2()) &&
                        (sub_ack->getReasonCode() == sub_req->getSubOptions())) {
                        cout << "Verbindungsaufbau erfolgreich!!!" << endl;


                        close(my_socket);
                        return 0;
                    } else {
                        cout << "Verbindungsaufbau NICHT erfolgreich!!!" << endl;
                        close(my_socket);
                        return -1;
                    }
                }
            } else {
                perror("ERROR: received not valid ack");
                close(my_socket);
                return -1;
            }

            break;
        }

        default:
            break;
    }

    //Release TLS socket
    SSL_shutdown(ssl);
    SSL_free(ssl);

    //Close TCP socket
    close(my_socket);

    //Release SSL context
    SSL_CTX_free(ctx);

    //Cleanup OpenSSL
    cleanup_openssl();

    return 0;
}

void parse_config() {
    ifstream config(filename, ifstream::in);

    string line;


    while (getline(config, line)) {
        int pos = line.find('=');
        string key = line.substr(0, pos);
        string value = line.substr(pos + 1, line.length());

        if (key == "ip") {
            ip = value;
        }

        if (key == "port") {
            port = stoi(value);
        }

        if (key == "clientid") {
            clientid = value;
        }

        if (key == "topic") {
            topic = value;
        }

        if (key == "qos") {
            qos = stoi(value);
        }
    }

    config.close();
}

int create_socket() {
    int my_socket;

    my_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (my_socket == -1) {
        perror("ERROR: Failed to create TCP-Socket");
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

    method = TLS_client_method();

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

    bio_keylog = BIO_new_file("tls__keys.log", "a");
    if (bio_keylog == NULL) {
        perror("ERROR: writing writing keylogfile");
    }

    if (BIO_tell(bio_keylog) == 0) {
        BIO_puts(bio_keylog,
                 "# SSL/TLS secrets log file, generated by OpenSSL\n");
        (void) BIO_flush(bio_keylog);
    }

    SSL_CTX_set_keylog_callback(ctx, keylog_callback);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT
                                        | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_sess_set_new_cb(ctx, new_session_cb);

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

static void keylog_callback(const SSL *ssl, const char *line) {
    if (bio_keylog == NULL) {
        perror("ERROR: Keylog callback is invoked without valid file!\n");
        return;
    }

    BIO_printf(bio_keylog, "%s\n", line);
    (void) BIO_flush(bio_keylog);
}

static int new_session_cb(SSL *s, SSL_SESSION *sess) {

    session_log = BIO_new_file("session.log", "w");

    if (session_log == NULL) {
        perror("Error writing session file %s\n");
    } else {
        PEM_write_bio_SSL_SESSION(session_log, sess);
    }

    /*
     * Session data gets dumped on connection for TLSv1.2 and below, and on
     * arrival of the NewSessionTicket for TLSv1.3.
     */

    session_key = BIO_new_file("session_ticket.log", "w");

    if (SSL_version(s) == TLS1_3_VERSION) {
        //BIO_printf(session_key,"---\nPost-Handshake New Session Ticket arrived:\n");
        SSL_SESSION_print(session_key, sess);
        //BIO_printf(session_log, "---\n");
    }

    BIO_free(session_log);
    BIO_free(session_key);

    return 0;
}