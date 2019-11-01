//
// Created by Tim Fehr on 12.09.19.
//

#ifndef MQTT_SERVER_SHORT_CONNECT_H
#define MQTT_SERVER_SHORT_CONNECT_H


#include "Packet.h"
#include "Connect_Packet.h"
#include "Subscribe_Request.h"

class Short_Connect{
private:
    Connect_Packet con;
    Subscribe_Request sub_req;

public:
    Short_Connect();
    
    explicit Short_Connect(uint8_t *buffer);

    Connect_Packet &getCon();

    void setCon(const Connect_Packet &con);

    Subscribe_Request &getSubReq();

    void setSubReq(const Subscribe_Request &subReq);

    string build_packet();

    void calc_msg_length();
};


#endif //MQTT_SERVER_SHORT_CONNECT_H
