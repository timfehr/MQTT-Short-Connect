//
// Created by Tim Fehr on 11.09.19.
//

#ifndef MQTT_SERVER_SUBSCRIBE_REQUEST_H
#define MQTT_SERVER_SUBSCRIBE_REQUEST_H

#include "Packet.h"

class Subscribe_Request : public Packet{
private:
    uint8_t msg_id_1;
    uint8_t msg_id_2;
    uint8_t topic_length_1{};
    uint8_t topic_length_2{};
    string topic;
    uint8_t sub_options;

public:
    Subscribe_Request();

    explicit Subscribe_Request(uint8_t *buffer);

    ~Subscribe_Request() override;

    [[nodiscard]] uint8_t getTopicLength1() const;

    void setTopicLength1(uint8_t topicLength1);

    [[nodiscard]] uint8_t getTopicLength2() const;

    void setTopicLength2(uint8_t topicLength2);

    [[nodiscard]] string getTopic() const;

    void setTopic(string t);

    [[nodiscard]] uint8_t getSubOptions() const;

    void setSubOptions(uint8_t subOptions);

    [[nodiscard]] uint8_t getMsgId_1() const;

    void setMsgId_1(uint8_t msgId_1);

    [[nodiscard]] uint8_t getMsgId_2() const;

    void setMsgId_2(uint8_t msgId_2);

    string build_packet() override;

    void calc_msg_length() override;

    void calc_topic_length ();

    void set_all(uint8_t *buffer);
    void set_all(uint8_t *buffer, int offset);

    bool validate();
};


#endif //MQTT_SERVER_SUBSCRIBE_REQUEST_H
