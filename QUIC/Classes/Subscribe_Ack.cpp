//
// Created by Tim Fehr on 11.09.19.
//

#include "Subscribe_Ack.h"

Subscribe_Ack::Subscribe_Ack() {
    this->fixed_header  = 0x90;
    this->properties    = 0x00;
    this->msg_length    = 0x00;
}

uint8_t Subscribe_Ack::getMsgId1() const {
    return msg_id_1;
}

void Subscribe_Ack::setMsgId1(uint8_t msgId1) {
    msg_id_1 = msgId1;
}

uint8_t Subscribe_Ack::getMsgId2() const {
    return msg_id_2;
}

void Subscribe_Ack::setMsgId2(uint8_t msgId2) {
    msg_id_2 = msgId2;
}

uint8_t Subscribe_Ack::getReasonCode() const {
    return reason_code;
}

void Subscribe_Ack::setReasonCode(uint8_t reasonCode) {
    reason_code = reasonCode;
}

string Subscribe_Ack::build_packet() {
    string sub_ack ;
    stringstream tmp;
    tmp << this->fixed_header << this->msg_length << this->msg_id_1 << this->msg_id_2 << this->properties << this->reason_code;
    sub_ack = tmp.str();
    return sub_ack;
}

void Subscribe_Ack::calc_msg_length() {
    this->msg_length = sizeof(this->msg_id_1) + sizeof(this->msg_id_2) + sizeof(this->properties) + sizeof(this->reason_code);
}

void Subscribe_Ack::set_all(const uint8_t *buffer) {
    this->fixed_header  = buffer[0];
    this->msg_length    = buffer[1];
    this->msg_id_1      = buffer[2];
    this->msg_id_2      = buffer[3];
    this->properties    = buffer[4];
    this->reason_code   = buffer[5];
}

bool Subscribe_Ack::validate() {
    return this->fixed_header == 0x90;
}

Subscribe_Ack::Subscribe_Ack(const uint8_t *buffer) {
    this->fixed_header  = buffer[0];
    this->msg_length    = buffer[1];
    this->msg_id_1      = buffer[2];
    this->msg_id_2      = buffer[3];
    this->properties    = buffer[4];
    this->reason_code   = buffer[5];
}
