#include <iostream>
#include <sys/socket.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <netinet/in.h>
#include <unistd.h>
#include <quant/quant.h>
#include <sys/param.h>
#include <netdb.h>
#include <net/if.h>
#include "Classes/Connect_Packet.h"
#include "Classes/Connect_Ack.h"
#include "Classes/Subscribe_Request.h"
#include "Classes/Subscribe_Ack.h"
#include "Classes/Short_Connect.h"
#include "Classes/Short_Ack.h"

using namespace std;

enum Packets {CONNECT, CONNECT_ACK, SUBSCRIBE_REQUEST, SUBSCRIBE_ACK, SHORT_CONNECT, SHORT_CONNECT_ACK};

struct cb_data {
    struct q_stream * s;
    struct q_conn * c;
    struct w_engine * w;
    int dir;
    int af;
};

struct conn_cache_entry {
    struct sockaddr_in dst;
    struct q_conn * c;
#ifndef NO_MIGRATION
    bool rebound;
    uint8_t _unused[7];
#endif
};

KHASH_MAP_INIT_INT64(conn_cache, struct conn_cache_entry *)

static uint32_t timeout = 10;
static uint32_t num_bufs = 100000;
static uint32_t reps = 1;
static bool do_h3 = false;
static bool flip_keys = false;
static bool zlen_cids = false;
static bool write_files = false;
#ifndef NO_MIGRATION
static bool rebind = false;
static bool migrate = false;
#endif

struct stream_entry {
    sl_entry(stream_entry) next;
    struct q_conn * c;
    struct q_stream * s;
    char * url;
    struct timespec req_t;
    struct timespec rep_t;
    struct w_iov_sq req;
    struct w_iov_sq rep;
};

static inline uint64_t __attribute__((nonnull))

conn_cache_key(const struct sockaddr * const sock)
{
    const struct sockaddr_in * const sock4 =
            (const struct sockaddr_in *)(const void *)sock;

    return ((uint64_t)sock4->sin_addr.s_addr
            << sizeof(sock4->sin_addr.s_addr) * 8) |
           (uint64_t)sock4->sin_port;
}

static sl_head(stream_list, stream_entry) sl = sl_head_initializer(sl);

static struct q_conn * __attribute__((nonnull)) get(struct w_engine * const w, khash_t(conn_cache) * cc, string data, bool new_stream)
{
    char dest[1024] = {0};
    char port[64];
    //char data[2048];

    string tmp = "127.0.0.1";
    strcpy(dest, tmp.c_str());
    tmp = "8883";
    strcpy(port, tmp.c_str());

    struct addrinfo * peer;

    const struct addrinfo hints = {.ai_family = AF_INET,
            .ai_socktype = SOCK_DGRAM,
            .ai_protocol = IPPROTO_UDP};
    const int err = getaddrinfo(dest, port, &hints, &peer);

    if (err) {
        printf("ERROR: getaddrinfo: %s", gai_strerror(err));
        freeaddrinfo(peer);
        return 0;
    }

    // add to stream list
    struct stream_entry *se = static_cast<stream_entry *>(calloc(1, sizeof(*se)));
    ensure(se, "calloc failed");
    sq_init(&se->rep);
    sl_insert_head(&sl, se, next);

    sq_init(&se->req);

        char req_str[MAXPATHLEN + 6];
        //const int req_str_len = snprintf(req_str, sizeof(req_str), "%s", data);
        memcpy(req_str, data.c_str(), data.length());
        q_chunk_str(w, peer->ai_family, req_str, data.length(), &se->req);

        cout << "Size: " << data.length() << endl << "req_str: " << req_str << endl;

    // do we have a connection open to this peer?
    khiter_t k = kh_get(conn_cache, cc, conn_cache_key(peer->ai_addr));
    struct conn_cache_entry * cce = (k == kh_end(cc) ? 0 : kh_val(cc, k)); // NOLINT
    const bool opened_new = cce == 0;

    if (cce == 0) {
        clock_gettime(CLOCK_MONOTONIC, &se->req_t);
        struct q_conn * const c = q_connect(
                w, peer->ai_addr, dest,
#ifndef NO_MIGRATION
                rebind ? 0 : &se->req, rebind ? 0 : &se->s,
#else
                0, 0,
#endif
                true,
                do_h3 ? "h3-" DRAFT_VERSION_STRING : "hq-" DRAFT_VERSION_STRING, 0);

        if (c == 0) {
            freeaddrinfo(peer);
            return 0;
        }

        cce = static_cast<conn_cache_entry *>(calloc(1, sizeof(*cce)));
        ensure(cce, "calloc failed");
        cce->c = c;

        // insert into connection cache
        cce->dst = *(struct sockaddr_in *)&peer->ai_addr;
        int ret;
        k = kh_put(conn_cache, cc, conn_cache_key(peer->ai_addr), &ret);
        ensure(ret >= 1, "inserted returned %d", ret);
        kh_val(cc, k) = cce;
    }

    if (opened_new == false
        #ifndef NO_MIGRATION
        || (rebind && cce->rebound == false)
#endif
            ) {
        se->s = q_rsv_stream(cce->c, true);

        if (se->s) {
            clock_gettime(CLOCK_MONOTONIC, &se->req_t);
            q_write(se->s, &se->req, true);
#ifndef NO_MIGRATION
            if (rebind && cce->rebound == false) {
                q_rebind_sock(cce->c, migrate);
                cce->rebound = true; // only rebind once
            }
#endif
        }
    }

    se->c = cce->c;
    freeaddrinfo(peer);
    return cce->c;
}

static void free_se(struct stream_entry * const se)
{
    q_free(&se->req);
    q_free(&se->rep);
    free(se);
}

static void free_sl_head(void)
{
    struct stream_entry * const se = sl_first(&sl);
    sl_remove_head(&sl, next);
    free_se(se);
}

static void free_sl(void)
{
    while (sl_empty(&sl) == false)
        free_sl_head();
}

int getPacketType(const uint8_t *buffer) {
    //Short Connect ack
    if(buffer[0] == 0x20 && buffer[2] == 0x02) {
        return SHORT_CONNECT_ACK;
    }

    //Normal Ack
    if (buffer[0] == 0x20) {
        return CONNECT_ACK;
    }

    //Subscribe Ack
    if(buffer[0] == 0x90) {
        return SUBSCRIBE_ACK;
    }
}

int main(int argc, char *argv[]) {
    char ifname[IFNAMSIZ] = "lo0";
    int ch;
    char cache[MAXPATHLEN] = "session.log";
    char tls_log[MAXPATHLEN] = "keys.log";
    char qlog[MAXPATHLEN] = "qlog.qlog";
    bool verify_certs = false;
    int ret = 0;
    string clientid = "Client 1";
    string topic = "TestTopic";
    int qos = 0;
    int packettype;
    string input;
    string connect_packet;
    string sub_packet;
    auto *short_con = new Short_Connect();
    auto *con = new Connect_Packet();
    auto *sub = new Subscribe_Request;
    uint8_t *res;

    cout << "Short Connect verwenden? ";
    cin >> input;

    if (input == "y") {
        //Set all variables
        short_con->getCon().setClientid(clientid);
        short_con->getCon().calc_clientid_length();
        short_con->getSubReq().setTopic(topic);
        short_con->getSubReq().setSubOptions(qos);
        short_con->getSubReq().calc_topic_length();
        short_con->calc_msg_length();

        //Build packet to send
        connect_packet = short_con->build_packet();
    } else if (input == "n") {
        //Set all variables
        con->setClientid(clientid);
        con->calc_clientid_length();
        con->calc_msg_length();

        //Build packet to send
        connect_packet = con->build_packet();

        sub->setTopic(topic);
        sub->setSubOptions(qos);
        sub->calc_topic_length();
        sub->calc_msg_length();

        sub_packet = sub->build_packet();
    }

    q_conn_conf *qcc = new q_conn_conf();
    qcc->enable_tls_key_updates = flip_keys;
    qcc->idle_timeout = timeout;
    qcc->enable_spinbit = true;
    qcc->enable_zero_len_cid = zlen_cids;

    struct q_conf qc{.conn_conf = qcc, .ticket_store=cache, .tls_log= tls_log, .qlog=qlog, .num_bufs=num_bufs, .enable_tls_cert_verify=verify_certs};

    struct w_engine *const w = q_init(ifname, &(qc));

    khash_t(conn_cache) * cc = kh_init(conn_cache);

    struct q_conn *c = get(w, cc, connect_packet, true);

    bool all_closed;
    do {
        all_closed = true;
        bool rxed_new = false;
        struct stream_entry * se = 0;
        struct stream_entry * tmp = 0;
        sl_foreach_safe (se, &sl, next, tmp) {
            if (se->c == 0 || se->s == 0 || q_is_conn_closed(se->c)) {
                sl_remove(&sl, se, stream_entry, next);
                free_se(se);
                continue;
            }

            rxed_new |= q_read_stream(se->s, &se->rep, false);

            const bool is_closed = q_peer_closed_stream(se->s);
            all_closed &= is_closed;
            if (is_closed)
                clock_gettime(CLOCK_MONOTONIC, &se->rep_t);
        }

        if (rxed_new == false) {
            struct q_conn * c;
            q_ready(w, timeout * NS_PER_S, &c);
            if (c == 0)
                break;
        }

    } while (all_closed == false);

    while (sl_empty(&sl) == false) {
        struct stream_entry * const se = sl_first(&sl);
        ret |= w_iov_sq_cnt(&se->rep) == 0;

        struct w_iov * v;
        char cid_str[64];
        q_cid(se->c, cid_str, sizeof(cid_str));

        q_stream_get_written(se->s, &se->req);

        uint32_t n = 0;

        sq_foreach (v, &se->rep, next) {
            const bool is_last = v == sq_last(&se->rep, struct w_iov, next);

            if (n < 4 || is_last) {
                res = new uint8_t[static_cast<int> (v->len)];
                memcpy(res, v->buf, static_cast<int> (v->len));
                cout << res << endl;
            }
        }

        q_free_stream(se->s);
        free_sl_head();
    }

    packettype = getPacketType(res);
    do {
        switch(packettype) {
            case SHORT_CONNECT_ACK: {
                //Short Connect Ack
                auto short_ack = new Short_Ack(res);
                if (short_ack->validate(short_con)) {
                    cout << "Short Connect erfolgreich!" << endl;
                    break;
                } else {
                    //Go to case 2 (no break) to send the Subscribe Request
                }
            }

            case CONNECT_ACK: {
                //Normal Ack -> send Subscribe request

                auto ack = new Connect_Ack(res);

                if (ack->validate()) {
                    c = get(w, cc, sub_packet, false);

                    do {
                        all_closed = true;
                        bool rxed_new = false;
                        struct stream_entry * se = 0;
                        struct stream_entry * tmp = 0;
                        sl_foreach_safe (se, &sl, next, tmp) {
                            if (se->c == 0 || se->s == 0 || q_is_conn_closed(se->c)) {
                                sl_remove(&sl, se, stream_entry, next);
                                free_se(se);
                                continue;
                            }

                            rxed_new |= q_read_stream(se->s, &se->rep, false);

                            const bool is_closed = q_peer_closed_stream(se->s);
                            all_closed &= is_closed;
                            if (is_closed)
                                clock_gettime(CLOCK_MONOTONIC, &se->rep_t);
                        }

                        if (rxed_new == false) {
                            struct q_conn * c;
                            q_ready(w, timeout * NS_PER_S, &c);
                            if (c == 0)
                                break;
                        }

                    } while (all_closed == false);

                    while (sl_empty(&sl) == false) {
                        struct stream_entry * const se = sl_first(&sl);
                        ret |= w_iov_sq_cnt(&se->rep) == 0;

                        char cid_str[64];
                        q_cid(se->c, cid_str, sizeof(cid_str));

                        q_stream_get_written(se->s, &se->req);

                        struct w_iov * v;
                        uint32_t n = 0;

                        sq_foreach (v, &se->rep, next) {
                            const bool is_last = v == sq_last(&se->rep, struct w_iov, next);

                            if (n < 4 || is_last) {
                                res = new uint8_t[static_cast<int> (v->len)];
                                memcpy(res, v->buf, static_cast<int> (v->len));
                                cout << res << endl;
                            }
                        }

                        q_free_stream(se->s);
                        free_sl_head();
                    }

                    packettype = getPacketType(res);
                } else {
                    cout << "Kein Valides Connect Ack bekommen!" << endl;
                }

                break;
            }

            case SUBSCRIBE_ACK: {
                //Subscribe Ack
                auto sub_ack = new Subscribe_Ack(res);

                if(sub_ack->validate()) {
                    cout << "Normales Connect erfolgreich" << endl;
                    packettype = 4;
                } else {
                    cout << "Subscribe Ack bekommen, aber nicht valide" << endl;
                }

                break;
            }

            default: {
                cout << "Fehlerhaftes Packet erhalten" << endl;
            }
        }
    } while (packettype == 2 || packettype == 3);


    return 0;
}