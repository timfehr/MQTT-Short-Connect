//
// Created by Tim Fehr on 12.09.19.
//

#include "Short_Connect.h"

Connect_Packet &Short_Connect::getCon() {
    return con;
}

void Short_Connect::setCon(const Connect_Packet &con) {
    Short_Connect::con = con;
}

Subscribe_Request &Short_Connect::getSubReq(){
    return sub_req;
}

void Short_Connect::setSubReq(const Subscribe_Request &subReq) {
    sub_req = subReq;
}

Short_Connect::Short_Connect() {
    this->con.setConnectFlags(0x03);
}

string Short_Connect::build_packet() {
    string short_con ;
    stringstream tmp;
    tmp << con.build_packet() << this->sub_req.getMsgId_1() << this->sub_req.getMsgId_2() << this->sub_req.getTopicLength1() << this->sub_req.getTopicLength2() << this->sub_req.getTopic() << this->sub_req.getSubOptions();
    short_con = tmp.str();
    return short_con;
}

void Short_Connect::calc_msg_length() {
    this->con.calc_msg_length();
    this->sub_req.calc_msg_length();

    size_t msg_length = this->con.getMsgLength() + this->sub_req.getMsgLength() - sizeof(this->sub_req.getProperties());

    this->con.setMsgLength(static_cast<uint8_t>(msg_length));    // Properties kommen doppelt vor, deswegen nur einmal berechnen
}

Short_Connect::Short_Connect(uint8_t *buffer) {
    int offset = con.set_all(buffer);

    this->sub_req.set_all(buffer, offset);
}
