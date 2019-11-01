//
// Created by Tim Fehr on 11.09.19.
//

#include "Connect_Packet.h"

#include <utility>

Connect_Packet::Connect_Packet() {
    fixed_header        = 0x10;
    prot_length_msb     = 0x00; //Protocoll Length Most Significant Bit
    prot_length_lsb     = 0x04; //Protocoll Length Least Significant Bit -> fixe Länge 4
    prot_name[0]        = 0x4d; //"M"
    prot_name[1]        = 0x51; //"Q"
    prot_name[2]        = 0x54; //"T"
    prot_name[3]        = 0x54; //"T"
    prot_version        = 0x05; //"5"
    connect_flags       = 0x02; //Clean Session Flag gesetzt
    keep_alive_msb      = 0x00; //Keep Alive Most Significant Bit
    keep_alive_lsb      = 0x3c; //Keep Alive Least Significant Bit
    clientid_length_1   = 0x00;
    clientid_length_2   = 0x00;
}

Connect_Packet::~Connect_Packet() = default;

uint8_t Connect_Packet::getProtLengthMsb() const {
    return prot_length_msb;
}

void Connect_Packet::setProtLengthMsb(uint8_t protLengthMsb) {
    prot_length_msb = protLengthMsb;
}

uint8_t Connect_Packet::getProtLengthLsb() const {
    return prot_length_lsb;
}

void Connect_Packet::setProtLengthLsb(uint8_t protLengthLsb) {
    prot_length_lsb = protLengthLsb;
}


uint8_t Connect_Packet::getProtVersion() const {
    return prot_version;
}

void Connect_Packet::setProtVersion(uint8_t protVersion) {
    prot_version = protVersion;
}

uint8_t Connect_Packet::getConnectFlags() const {
    return connect_flags;
}

void Connect_Packet::setConnectFlags(uint8_t connectFlags) {
    connect_flags = connectFlags;
}

uint8_t Connect_Packet::getKeepAliveMsb() const {
    return keep_alive_msb;
}

void Connect_Packet::setKeepAliveMsb(uint8_t keepAliveMsb) {
    keep_alive_msb = keepAliveMsb;
}

uint8_t Connect_Packet::getKeepAliveLsb() const {
    return keep_alive_lsb;
}

void Connect_Packet::setKeepAliveLsb(uint8_t keepAliveLsb) {
    keep_alive_lsb = keepAliveLsb;
}

uint8_t Connect_Packet::getClientidLength1() const {
    return clientid_length_1;
}

void Connect_Packet::setClientidLength1(uint8_t clientidLength1) {
    clientid_length_1 = clientidLength1;
}

uint8_t Connect_Packet::getClientidLength2() const {
    return clientid_length_2;
}

void Connect_Packet::setClientidLength2(uint8_t clientidLength2) {
    clientid_length_2 = clientidLength2;
}

string Connect_Packet::getClientid() const {
    return clientid;
}

void Connect_Packet::setClientid(string id) {
    clientid = std::move(id);
    this->clientid.shrink_to_fit();
}

string Connect_Packet::build_packet() {
    string packet;
    std::stringstream tmp;
    tmp << this->fixed_header << this->msg_length << this->prot_length_msb << this->prot_length_lsb << this->prot_name[0] << this->prot_name[1] << this->prot_name[2] << this->prot_name[3] << this->prot_version << this->connect_flags << this->keep_alive_msb << this->keep_alive_lsb << this->properties << this->clientid_length_1 << this->clientid_length_2 << this->clientid;
    packet = tmp.str();
    return packet;
}

void Connect_Packet::calc_msg_length() {
    this->msg_length = sizeof(prot_length_msb) + sizeof(prot_length_msb) + sizeof(prot_name) + sizeof(prot_version) + sizeof(connect_flags) + sizeof(keep_alive_msb) + sizeof(keep_alive_lsb) + sizeof(properties) + sizeof(clientid_length_1) + sizeof(clientid_length_2) + (size_t)clientid.size();
}

void Connect_Packet::calc_clientid_length() {
    this->clientid_length_2 = static_cast<uint8_t>((size_t) clientid.size());
}

int Connect_Packet::set_all(uint8_t *buffer) {
    this->fixed_header      = buffer[0];
    this->msg_length        = buffer[1];
    this->prot_length_msb   = buffer[2];
    this->prot_length_lsb   = buffer[3];
    this->prot_name[0]      = buffer[4];
    this->prot_name[1]      = buffer[5];
    this->prot_name[2]      = buffer[6];
    this->prot_name[3]      = buffer[7];
    this->prot_version      = buffer[8];
    this->connect_flags     = buffer[9];
    this->keep_alive_msb    = buffer[10];
    this->keep_alive_lsb    = buffer[11];
    this->properties        = buffer[12];
    this->clientid_length_1 = buffer[13];
    this->clientid_length_2 = buffer[14];

    int i;

    for (i = 0; i < this->clientid_length_2; i++) {
        this->clientid += buffer[15 + i];
    }

    return 14 + i;
}

string Connect_Packet::getProtName() const {
    string tmp;
    for (int value:prot_name) tmp += (char)value;
    return tmp;
}

bool Connect_Packet::validate() {
    return this->fixed_header == 0x10;
}

Connect_Packet::Connect_Packet(uint8_t *buffer) {
    this->fixed_header      = buffer[0];
    this->msg_length        = buffer[1];
    this->prot_length_msb   = buffer[2];
    this->prot_length_lsb   = buffer[3];
    this->prot_name[0]      = buffer[4];
    this->prot_name[1]      = buffer[5];
    this->prot_name[2]      = buffer[6];
    this->prot_name[3]      = buffer[7];
    this->prot_version      = buffer[8];
    this->connect_flags     = buffer[9];
    this->keep_alive_msb    = buffer[10];
    this->keep_alive_lsb    = buffer[11];
    this->properties        = buffer[12];
    this->clientid_length_1 = buffer[13];
    this->clientid_length_2 = buffer[14];

    int i;

    for (i = 0; i < this->clientid_length_2; i++) {
        this->clientid += buffer[15 + i];
    }
}


