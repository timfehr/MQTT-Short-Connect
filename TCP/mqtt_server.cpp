#pragma clang diagnostic push
#pragma ide diagnostic ignored "hicpp-signed-bitwise"
#include <iostream>
#include <sys/socket.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unistd.h> // for read, write...
#include <cstring>
#include "Classes/Connect_Packet.h"
#include "Classes/Connect_Ack.h"
#include "Classes/Subscribe_Request.h"
#include "Classes/Subscribe_Ack.h"
#include "Classes/Short_Connect.h"
#include "Classes/Short_Ack.h"

#define SERV_TCP_PORT 1883

using namespace std;

void debug_output_connect_header(Connect_Packet *tmp);
void debug_output_short_connect(Short_Connect *sc);

int check_short_connect(const uint8_t *buffer);

int main() {
    int my_socket, clilen, childpid, newsocket;
    ssize_t valread;
    struct sockaddr_in client_addr{}, serv_addr{};

    int result = -1;
    char *ip;
    int port;
    int addr_len = 0;

    uint8_t buffer[1024] = {0};
    string nachrichtt;

    //Create socket
    if ((my_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("ERROR: failed to create TCP-Socket");
    }

    //Set socket options
    int optvar = 1;
    result = setsockopt(my_socket, SOL_SOCKET, SO_REUSEADDR, &optvar, sizeof(optvar));

    if (result < 0) {
        perror("Option REUSEADDR could not be set");
    }

#ifdef __linux__
    int flag = 5;

    if(setsockopt(my_socket, IPPROTO_TCP, TCP_FASTOPEN, &flag, sizeof(flag))) {
        perror("Option TCP_FASTOPEN could not be set");
    }
#endif

    int flags = 1;
    if (setsockopt(my_socket, IPPROTO_TCP, TCP_NODELAY, (void *) &flags, sizeof(flags))) {
        perror("ERROR: Could not set TCP_NODELAY option");
    }


    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(SERV_TCP_PORT);

    //Bind socket to ip and port
    if (::bind(my_socket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) == -1) {
        perror("ERROR: Cannot bind local address");
    }

    cout << "Ready for connections..." << endl;

    //Set socket to listen
    listen(my_socket, 5);
    addr_len = sizeof(struct sockaddr_in);
    clilen = sizeof(client_addr);

#ifdef __APPLE__
    int flag = 1;

    if(setsockopt(my_socket, IPPROTO_TCP, TCP_FASTOPEN, &flag, sizeof(flag))) {
        perror("Option TCP_FASTOPEN could not be set");
    }
#endif

    //Endlosschleife um Verbindungen anzunehmen
    while (true) {
        //Verbindung annehmen -> blockiert bis Verbindung kommt
        newsocket = accept(my_socket, (struct sockaddr *) &client_addr, (socklen_t *) &clilen);
        if (newsocket > 0) {
            ip = inet_ntoa(client_addr.sin_addr);
            port = ntohs(client_addr.sin_port);
            //cout << "Client mit der IP " << ip << ":" << port << " verbunden!" << endl;
        } else {
            //cout << "Poll: Kein Client verbunden" << endl;
            sleep(1);
            continue;
        }

        //Create new prozess which handles the connection
        if ((childpid = fork()) < 0) {
            perror("server: Fork error");
            return -1;
        } else if (childpid == 0) {
            //Close old socket in this process, still alive in parent
            close(my_socket);

            //Debug outpu
            cout << "Success!" << endl;
            cout << "Client IP: " << ip << ":" << port << endl;

            //Wait for client to send data
            do {
                valread = read(newsocket, buffer, 1024);
            } while (valread < 0);

            int validate = check_short_connect(buffer);

            switch (validate) {
                case 0: {
                    cout << "Short Connect bekommen..." << endl;

                    auto *short_con = new Short_Connect(buffer);
                    auto *short_ack = new Short_Ack();

                    short_ack->setMsgId1(short_con->getSubReq().getMsgId_1());
                    short_ack->setMsgId2(short_con->getSubReq().getMsgId_2());
                    short_ack->getConAck().setReasonCode(short_con->getSubReq().getSubOptions());
                    short_ack->calc_msg_length();
                    string sa = short_ack->build_packet();
                    char ack[sa.size()];
                    memcpy(ack, sa.c_str(), sizeof(ack));

                    //Send Connect packet
                    if (send(newsocket, ack, sizeof(ack), 0) < 0) {
                        perror("ERROR: Could not send connect packet");
                    }

                    close(newsocket);

                    break;
                }

                case 1: {
                    cout << "Normales Connect bekommen..." << endl;

                    //Set all data and validate
                    auto *connect = new Connect_Packet(buffer);

                    debug_output_connect_header(connect);

                    if (connect->validate()) {
                        //Send Connect Ack
                        auto *con_ack = new Connect_Ack();

                        con_ack->calc_msg_length();
                        string ack = con_ack->build_packet();
                        char con[ack.size()];
                        memcpy(con, ack.c_str(), sizeof(con));

                        //Send Connect packet
                        if (send(newsocket, con, sizeof(con), 0) < 0) {
                            perror("ERROR: Could not send connect packet");
                        }

                        //Wait for response
                        do {
                            valread = read(newsocket, buffer, 1024);
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
                            if (send(newsocket, sas, sizeof(sas), 0) < 0) {
                                perror("ERROR: Could not send connect packet");
                            }
                        } else {
                            cout << "Kein valides Sub_Req mit Topic: " << sub_req->getTopic() << endl;
                            cout << "Sub Options: " << (int) sub_req->getSubOptions() << endl;
                        }
                    }

                    close(newsocket);

                    break;
                }

                case 2: {
                    perror("ERROR: Connect expected but it isn't");
                    close(newsocket);
                    return -1;
                }

                default:
                    break;
            }
        }
    }
}

void debug_output_connect_header(Connect_Packet *tmp) {
    cout << "Protokoll: " << tmp->getProtName() << endl;
    cout << "ClientID: " << tmp->getClientid() << endl;
}

void debug_output_short_connect(Short_Connect *sc) {
    cout << "Protokoll: " << sc->getCon().getProtName() << endl;
    cout << "ClientID: " << sc->getCon().getClientid() << endl;
    cout << "Topic: " << sc->getSubReq().getTopic() << endl;
    cout << "QoS: " << (int)sc->getSubReq().getSubOptions() << endl;
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

#pragma clang diagnostic pop
