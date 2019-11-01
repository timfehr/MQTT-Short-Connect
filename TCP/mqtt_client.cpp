#include <iostream>
#include <sys/socket.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <bitset>
#include <fstream>
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

void parse_config();

int main(int argc, char *argv[]) {
    auto *connect = new Connect_Packet();
    auto * sub_req = new Subscribe_Request();
    int my_socket;
    //const char* ip = "127.0.0.1";
    string mqtt_header;
    string mqtt_sub_req;
    string sc_input;
    uint8_t buffer[1024] = {0};
    ssize_t valread;
    char input;
    //string clientid, topic;

    parse_config();

    //Create Socket
    my_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (my_socket == -1) {
        perror("ERROR: Failed to create TCP-Socket");
        return -1;
    }

    int flags = 1;
    if (setsockopt(my_socket, IPPROTO_TCP, TCP_NODELAY, (void *) &flags, sizeof(flags))) {
        perror("ERROR: Could not set TCP_NODELAY option");
    }

    int option;
#ifdef __linux__
    int flag = 5;
    if(setsockopt(my_socket, IPPROTO_TCP, TCP_FASTOPEN, &flag, sizeof(flag))) {
        perror("Option TCP_FASTOPEN could not be set");
    }

    option = MSG_FASTOPEN;
#endif
    //Set socket options
    struct sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(1883);  // ggfs aendern! Port des Servers
    server_addr.sin_addr.s_addr = inet_addr(ip.c_str()); // ggfs Aendern! IP Adresse des Servers, z.B. "localhost"

#ifdef __APPLE__
    sa_endpoints_t endpoints;
    endpoints.sae_srcif = 0;
    endpoints.sae_srcaddr = NULL;
    endpoints.sae_srcaddrlen = 0;
    endpoints.sae_dstaddr = (struct sockaddr *)&server_addr;
    endpoints.sae_dstaddrlen = sizeof(server_addr);

    //Connect to server
    if (::connectx(my_socket, &endpoints, SAE_ASSOCID_ANY,
                   CONNECT_DATA_IDEMPOTENT | CONNECT_RESUME_ON_READ_WRITE,
                   NULL, 0, NULL, NULL) < 0) {
        perror("ERROR: Could not Connect");
        return -1;
    }

    option = 0;
#endif
    //Ask User if he/she wants to use short connect
    cout << "Short Connect verwenden? ";
    cin >> input;

    switch (input) {
        case 'y': {
            cout << endl << "Short Connect wird vernwendet..." << endl;

            auto *short_con = new Short_Connect();

            //No ClientID and Topic specified by user, use default
            short_con->getCon().setClientid(clientid);
            short_con->getCon().calc_clientid_length();
            short_con->getSubReq().setTopic(topic);
            short_con->getSubReq().calc_topic_length();
            short_con->calc_msg_length();

            string mqtt_short = short_con->build_packet();
            char sc[mqtt_short.size()];
            memcpy(sc, mqtt_short.c_str(), sizeof(sc));

            //Send Short Connect packet
            if (sendto(my_socket, sc, sizeof(sc), option, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
                perror("ERROR: Could not send connect packet");
            }

            //Wait for Short Ack
            do {
                valread = read(my_socket, buffer, 1024);
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
            //Build Connect Packet
            connect->setClientid(clientid);
            connect->calc_clientid_length();
            connect->calc_msg_length();

            mqtt_header = connect->build_packet();
            char con[mqtt_header.size()];
            memcpy(con, mqtt_header.c_str(), sizeof(con));

            //Send Connect packet
            if (sendto(my_socket, con, sizeof(con), option, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
                perror("ERROR: Could not send connect packet");
            }

            //Wait for response
            do {
                valread = read(my_socket, buffer, 1024);
            } while (valread < 0);

            //Set the incoming data to the packet
            auto *conn_ack = new Connect_Ack(buffer);

            if (conn_ack->validate()) {
                //Send Subscribe Request
                sub_req->setTopic(topic);
                sub_req->calc_topic_length();
                sub_req->calc_msg_length();

                mqtt_sub_req = sub_req->build_packet();
                char req[mqtt_sub_req.size()];
                memcpy(req, mqtt_sub_req.c_str(), sizeof(req));

                //req[1] = sub_req->calc_msg_length();
                //req[6] = sub_req->calc_topic_length();

                if (send(my_socket, req, sizeof(con), 0) < 0) {
                    perror("ERROR: Could not send connect packet");
                }

                //Wait for Subscribe Ack
                do {
                    valread = read(my_socket, buffer, 1024);
                } while (valread < 0);

                //Set the incoming data
                auto *sub_ack = new Subscribe_Ack(buffer);

                //Validate if Subscribe Ack
                if (sub_ack->validate()) {
                    //Validate the same message identifier and the same QoS
                    if ((sub_ack->getMsgId1() == sub_req->getMsgId_1()) && (sub_ack->getMsgId2() == sub_req->getMsgId_2()) && (sub_ack->getReasonCode() == sub_req->getSubOptions())) {
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

    close(my_socket);

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

