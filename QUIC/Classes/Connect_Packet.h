//
// Created by Tim Fehr on 11.09.19.
//

#ifndef MQTT_SERVER_CONNECT_PACKET_H
#define MQTT_SERVER_CONNECT_PACKET_H

#include "Packet.h"

class Connect_Packet : public Packet{
protected:
    uint8_t prot_length_msb;    //Protocoll Length Most Significant Bit
    uint8_t prot_length_lsb;    //Protocoll Length Least Significant Bit -> fixe Länge 4
    uint8_t prot_name[4];
    uint8_t prot_version;       //"5"
    uint8_t connect_flags;
    uint8_t keep_alive_msb;     //Keep Alive Most Significant Bit
    uint8_t keep_alive_lsb;     //Keep Alive Least Significant Bit
    uint8_t clientid_length_1;  //Länge der ClientID
    uint8_t clientid_length_2;
    string clientid;            //ClientID -> Hier keine gesetzt

public:
    Connect_Packet();

    explicit Connect_Packet(uint8_t *buffer);

    ~Connect_Packet() override;

    [[nodiscard]] uint8_t getProtLengthMsb() const;

    void setProtLengthMsb(uint8_t protLengthMsb);

    [[nodiscard]] uint8_t getProtLengthLsb() const;

    void setProtLengthLsb(uint8_t protLengthLsb);

    [[nodiscard]] string getProtName() const;

    [[nodiscard]] uint8_t getProtVersion() const;

    void setProtVersion(uint8_t protVersion);

    [[nodiscard]] uint8_t getConnectFlags() const;

    void setConnectFlags(uint8_t connectFlags);

    [[nodiscard]] uint8_t getKeepAliveMsb() const;

    void setKeepAliveMsb(uint8_t keepAliveMsb);

    [[nodiscard]] uint8_t getKeepAliveLsb() const;

    void setKeepAliveLsb(uint8_t keepAliveLsb);

    [[nodiscard]] uint8_t getClientidLength1() const;

    void setClientidLength1(uint8_t clientidLength1);

    [[nodiscard]] uint8_t getClientidLength2() const;

    void setClientidLength2(uint8_t clientidLength2);

    [[nodiscard]] string getClientid() const;

    void setClientid(string clientid);

    string build_packet() override;

    void calc_msg_length() override;
    void calc_clientid_length ();

    int set_all(uint8_t *buffer);

    bool validate();
};

#endif //MQTT_SERVER_CONNECT_PACKET_H
