//
// Created by Tim Fehr on 11.09.19.
//

#ifndef MQTT_SERVER_PACKET_H
#define MQTT_SERVER_PACKET_H

#include <cstdio>
#include <string>
#include <cstdint>
#include <sstream>
#include <cstdio>
#include <cstring>

using namespace std;

class Packet {
protected:
    uint8_t fixed_header;
    uint8_t msg_length;
    uint8_t properties;

public:
    Packet();
    virtual ~Packet();

    [[nodiscard]] uint8_t getFixedHeader() const;
    [[nodiscard]] uint8_t getMsgLength() const;
    [[nodiscard]] uint8_t getProperties() const;

    void setFixedHeader(uint8_t fixedHeader);
    void setMsgLength(uint8_t msgLength);
    void setProperties(uint8_t properties);

    virtual string build_packet() = 0;
    virtual void calc_msg_length() = 0;
};

#endif //MQTT_SERVER_PACKET_H
