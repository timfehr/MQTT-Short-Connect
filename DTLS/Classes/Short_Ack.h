//
// Created by Tim Fehr on 12.09.19.
//

#ifndef MQTT_SERVER_SHORT_ACK_H
#define MQTT_SERVER_SHORT_ACK_H

#include "Connect_Ack.h"
#include "Short_Connect.h"

class Short_Ack {
private:
    Connect_Ack con_ack;
    uint8_t msg_id_1{};
    uint8_t msg_id_2{};
public:
    Short_Ack();
    
    explicit Short_Ack(uint8_t *buffer);

    Connect_Ack &getConAck();

    void setConAck(const Connect_Ack &conAck);

    [[nodiscard]] uint8_t getMsgId1() const;

    void setMsgId1(uint8_t msgId1);

    [[nodiscard]] uint8_t getMsgId2() const;

    void setMsgId2(uint8_t msgId2);

    string build_packet();

    void calc_msg_length();

    bool validate(Short_Connect *con);
};


#endif //MQTT_SERVER_SHORT_ACK_H
