//
// Created by Tim Fehr on 11.09.19.
//

#ifndef MQTT_SERVER_CONNECT_ACK_H
#define MQTT_SERVER_CONNECT_ACK_H


#include "Packet.h"

class Connect_Ack : public Packet{
protected:
    uint8_t ack_flags;
    uint8_t reason_code;
public:
    Connect_Ack();

    explicit Connect_Ack(const uint8_t *buffer);

    [[nodiscard]] uint8_t getAckFlags() const;

    void setAckFlags(uint8_t ackFlags);

    [[nodiscard]] uint8_t getReasonCode() const;

    void setReasonCode(uint8_t reasonCode);

    string build_packet() override;

    void calc_msg_length() override;

    int set_all(const uint8_t *buffer);

    bool validate();
};


#endif //MQTT_SERVER_CONNECT_ACK_H
