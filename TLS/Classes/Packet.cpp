//
// Created by Tim Fehr on 11.09.19.
//

#include "Packet.h"

Packet::Packet() {
    fixed_header = 0x00;
    msg_length = 0x00;
    properties = 0x00;
}

Packet::~Packet() = default;

uint8_t Packet::getFixedHeader() const {
    return fixed_header;
}

uint8_t Packet::getMsgLength() const {
    return msg_length;
}

uint8_t Packet::getProperties() const {
    return properties;
}

void Packet::setFixedHeader(uint8_t fixedHeader) {
    fixed_header = fixedHeader;
}

void Packet::setMsgLength(uint8_t msgLength) {
    msg_length = msgLength;
}

void Packet::setProperties(uint8_t properties) {
    Packet::properties = properties;
}