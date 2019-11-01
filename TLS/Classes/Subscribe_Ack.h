//
// Created by Tim Fehr on 11.09.19.
//

#ifndef MQTT_SERVER_SUBSCRIBE_ACK_H
#define MQTT_SERVER_SUBSCRIBE_ACK_H


#include "Packet.h"

class Subscribe_Ack : public Packet{
protected:
    uint8_t msg_id_1{};
    uint8_t msg_id_2{};
    uint8_t reason_code{};

public:
    Subscribe_Ack();

    explicit Subscribe_Ack(const uint8_t *buffer);

    [[nodiscard]] uint8_t getMsgId1() const;

    void setMsgId1(uint8_t msgId1);

    [[nodiscard]] uint8_t getMsgId2() const;

    void setMsgId2(uint8_t msgId2);

    [[nodiscard]] uint8_t getReasonCode() const;

    void setReasonCode(uint8_t reasonCode);

    string build_packet() override;

    void calc_msg_length() override;

    void set_all(const uint8_t *buffer);

    bool validate();
};


#endif //MQTT_SERVER_SUBSCRIBE_ACK_H
