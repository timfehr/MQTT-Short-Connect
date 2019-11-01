//
// Created by Tim Fehr on 12.09.19.
//

#include "Short_Ack.h"

Short_Ack::Short_Ack() {
    con_ack.setAckFlags(0x02);
}

Connect_Ack &Short_Ack::getConAck(){
    return con_ack;
}

void Short_Ack::setConAck(const Connect_Ack &conAck) {
    con_ack = conAck;
}

uint8_t Short_Ack::getMsgId1() const {
    return msg_id_1;
}

void Short_Ack::setMsgId1(uint8_t msgId1) {
    msg_id_1 = msgId1;
}

uint8_t Short_Ack::getMsgId2() const {
    return msg_id_2;
}

void Short_Ack::setMsgId2(uint8_t msgId2) {
    msg_id_2 = msgId2;
}

string Short_Ack::build_packet() {
    string short_ack;
    stringstream tmp;
    tmp << con_ack.build_packet() << this->msg_id_1 << this->msg_id_2;
    short_ack = tmp.str();
    return short_ack;
}

void Short_Ack::calc_msg_length() {
    this->con_ack.calc_msg_length();

    size_t msg_length = this->con_ack.getMsgLength() + sizeof(this->msg_id_2) + sizeof(this->msg_id_1);

    this->con_ack.setMsgLength(msg_length);
}

bool Short_Ack::validate(Short_Connect *con) {
    return con_ack.getAckFlags() == 0x02 && con_ack.getReasonCode() == con->getSubReq().getSubOptions() &&
           msg_id_2 == con->getSubReq().getMsgId_2() && msg_id_1 == con->getSubReq().getMsgId_1();
}

Short_Ack::Short_Ack(uint8_t *buffer) {
    int offset = con_ack.set_all(buffer);

    this->msg_id_1 = buffer[offset + 0];
    this->msg_id_2 = buffer[offset + 1];
}
