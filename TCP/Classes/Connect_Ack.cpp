//
// Created by Tim Fehr on 11.09.19.
//

#include "Connect_Ack.h"

uint8_t Connect_Ack::getAckFlags() const {
    return ack_flags;
}

void Connect_Ack::setAckFlags(uint8_t ackFlags) {
    ack_flags = ackFlags;
}

uint8_t Connect_Ack::getReasonCode() const {
    return reason_code;
}

void Connect_Ack::setReasonCode(uint8_t reasonCode) {
    reason_code = reasonCode;
}

Connect_Ack::Connect_Ack() {
    this->fixed_header  = 0x20;
    this->msg_length    = 0x00;
    this->properties    = 0x00;
    this->ack_flags     = 0x00;
    this->reason_code   = 0x00;
}

string Connect_Ack::build_packet() {
    string ack;
    stringstream tmp;
    tmp << this->fixed_header << this->msg_length << this->ack_flags << this->reason_code << this->properties;
    ack = tmp.str();
    return ack;
}

void Connect_Ack::calc_msg_length() {
    this->msg_length = sizeof(this->ack_flags) + sizeof(this->reason_code) + sizeof(this->properties);
}

int Connect_Ack::set_all(const uint8_t *buffer) {
    this->fixed_header  = buffer[0];
    this->msg_length    = buffer[1];
    this->ack_flags     = buffer[2];
    this->reason_code   = buffer[3];
    this->properties    = buffer[4];

    return 5;
}

bool Connect_Ack::validate() {
    return this->fixed_header == 0x20 && this->reason_code == 0x00;
}

Connect_Ack::Connect_Ack(const uint8_t *buffer) {
    this->fixed_header  = buffer[0];
    this->msg_length    = buffer[1];
    this->ack_flags     = buffer[2];
    this->reason_code   = buffer[3];
    this->properties    = buffer[4];
}
