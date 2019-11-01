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
#include <quant/quant.h>
#include <sys/types.h>
#include <fcntl.h>
#include <libgen.h>
#include <net/if.h>
#include <stdbool.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>
#include "Classes/Connect_Packet.h"
#include "Classes/Connect_Ack.h"
#include "Classes/Subscribe_Request.h"
#include "Classes/Subscribe_Ack.h"
#include "Classes/Short_Connect.h"
#include "Classes/Short_Ack.h"

#define SERV_TCP_PORT 8883

using namespace std;

enum Packets {CONNECT, CONNECT_ACK, SHORT_CONNECT, SHORT_ACK, SUBSCRIBE_REQUEST, SUBSCRIBE_ACK, INVALID};

struct q_conn;

struct cb_data {
    struct q_stream * s;
    struct q_conn * c;
    struct w_engine * w;
    int dir;
    int af;
};

int getPacketType(const uint8_t *buffer) {
    //Short Connect
    if (buffer[0] == 0x10 && buffer[9] == 0x03) {
        return SHORT_CONNECT;
    }

    //Normal Connect
    if (buffer[0] == 0x10) {
        return CONNECT;
    }

    //Subscribe Request
    if (buffer[0] == 0x82) {
        return SUBSCRIBE_REQUEST;
    }

    return INVALID;
}


int main() {
    uint32_t timeout = 10;
    char ifname[IFNAMSIZ] = "lo0";
    char dir[MAXPATHLEN] = ".";
    char cert[MAXPATHLEN] = "cert.pem";
    char key[MAXPATHLEN] = "key.pem";
    char qlog[MAXPATHLEN] = QUANT "-server.qlog";
    uint16_t port = 8883;
    size_t num_ports = 1;
    uint32_t num_bufs = 100000;
    int ch;
    int ret = 0;

    const int dir_fd = open(dir, O_RDONLY | O_CLOEXEC);
    ensure(dir_fd != -1, "%s does not exist", dir);

    q_conn_conf *qcc = new q_conn_conf();
    qcc->idle_timeout = timeout;
    qcc->enable_spinbit = true;

    struct q_conf qc{.conn_conf=qcc, .tls_cert=cert, .tls_key=key, .qlog=qlog, .num_bufs=num_bufs};

    struct w_engine *const w = q_init(ifname, &qc);

    //Use IPv4 (idx = 0 for IPVv)
    uint16_t idx = 1;

    const struct q_conn * const c = q_bind(w, idx, port);

    //printf("%s %s %s %s:%d", "test",
    //     c ? "waiting on" : "failed to bind to", ifname,
    //     w_ntop(&w->ifaddr[idx].addr, ip_tmp), port);

    bool first_conn = true;

    while (true) {
        cout << "Äußerer Dauerschleife" << endl;

        while(true) {
            struct q_conn *c;
            const bool have_active = q_ready(w, first_conn ? 0 : timeout * NS_PER_S, &c);

            if (c == 0) {
                if (have_active == false)
                    break;
                continue;
            }

            first_conn = false;

            // do we need to q_accept?
            if (q_is_new_serv_conn(c))
                q_accept(w, 0);

            if (q_is_conn_closed(c)) {
                q_close(c, 0, 0);
                continue;
            }

            struct cb_data d = {.c = c, .w = w, .dir = dir_fd};
            again:
            struct w_iov_sq q = w_iov_sq_initializer(q);
            struct q_stream *s = q_read(c, &q, false);

            if (sq_empty(&q)) {
                if (s && q_is_stream_closed(s)) {
                    // retrieve the TX'ed request
                    q_stream_get_written(s, &q);

                    q_free_stream(s);
                    q_free(&q);
                    goto again;
                }
                continue;
            }

            if (q_is_uni_stream(s)) {
                printf("can't serve request on uni stream: %.*s", sq_first(&q)->len, sq_first(&q)->buf);
            } else {
                d.s = s;
                //d.af = sq_first(&q)->wv_af;
                struct w_iov *v;
                sq_foreach (v, &q, next) {
                    if (v->len == 0)
                        // skip empty bufs (such as pure FINs)
                        continue;

                    switch (getPacketType(v->buf)) {
                        case SHORT_CONNECT: {
                            //Short Connect
                            cout << "Short Connect bekommen" <<endl;

                            auto *short_con = new Short_Connect(v->buf);
                            auto *short_ack = new Short_Ack();

                            short_ack->setMsgId1(short_con->getSubReq().getMsgId_1());
                            short_ack->setMsgId2(short_con->getSubReq().getMsgId_2());
                            short_ack->getConAck().setReasonCode(short_con->getSubReq().getSubOptions());
                            short_ack->calc_msg_length();
                            string sa = short_ack->build_packet();
                            char ack[sa.length()];
                            memcpy(ack, sa.c_str(), sizeof(ack));
                            q_write_str(d.w, d.s, ack, sizeof(ack), true);

                            break;
                        }

                        case CONNECT: {
                            //Normal Connect
                            cout << "Normales Connect bekommen!" << endl;

                            auto con = new Connect_Packet(v->buf);

                            if (con->validate()) {
                                //Send Connect Ack
                                auto *con_ack = new Connect_Ack();

                                con_ack->calc_msg_length();
                                string ack = con_ack->build_packet();
                                char con[ack.size()];
                                memcpy(con, ack.c_str(), sizeof(con));

                                q_write_str(d.w, d.s, con, sizeof(con), true);
                            }

                            break;
                        }

                        case SUBSCRIBE_REQUEST: {
                            //Subscribe Request
                            cout << "Subscribe Request bekommen" << endl;

                            auto sub_req = new Subscribe_Request(v->buf);

                            if (sub_req->validate()) {
                                auto sub_ack = new Subscribe_Ack();

                                sub_ack->setMsgId1(sub_req->getMsgId_1());
                                sub_ack->setMsgId2(sub_req->getMsgId_2());
                                sub_ack->setReasonCode(sub_req->getSubOptions());
                                sub_ack->calc_msg_length();

                                string ack = sub_ack->build_packet();
                                char con[ack.size()];
                                memcpy(con, ack.c_str(), sizeof(con));

                                q_write_str(d.w, d.s, con, sizeof(con), true);

                                break;
                            }
                        }
                    }

                    goto again;
                }
            }

            q_free(&q);
        }

        printf("exiting\n");
    }

    q_cleanup(w);
    return ret;
}

