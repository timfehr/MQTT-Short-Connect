//
// Created by Tim Fehr on 11.09.19.
//

#include "Subscribe_Request.h"

#include <utility>

Subscribe_Request::Subscribe_Request() {
    this->fixed_header  = 0x82;
    this->msg_length    = 0x00;
    this->msg_id_1      = 0x28;
    this->msg_id_2      = 0x6c;
    this->properties    = 0x00;
    this->topic         = "";
    this->sub_options   = 0x01; //QoS 0
}

uint8_t Subscribe_Request::getTopicLength1() const {
    return topic_length_1;
}

void Subscribe_Request::setTopicLength1(uint8_t topicLength1) {
    topic_length_1 = topicLength1;
}

uint8_t Subscribe_Request::getTopicLength2() const {
    return topic_length_2;
}

void Subscribe_Request::setTopicLength2(uint8_t topicLength2) {
    topic_length_2 = topicLength2;
}

string Subscribe_Request::getTopic() const {
    return topic;
}

void Subscribe_Request::setTopic(string t){
    topic = std::move(t);
    this->topic.shrink_to_fit();
}

uint8_t Subscribe_Request::getSubOptions() const {
    return sub_options;
}

void Subscribe_Request::setSubOptions(uint8_t subOptions) {
    sub_options = subOptions;
}

uint8_t Subscribe_Request::getMsgId_1() const {
    return msg_id_1;
}

void Subscribe_Request::setMsgId_1(uint8_t msgId_1) {
    msg_id_1 = msgId_1;
}

uint8_t Subscribe_Request::getMsgId_2() const {
    return msg_id_2;
}

void Subscribe_Request::setMsgId_2(uint8_t msgId_2) {
    msg_id_2 = msgId_2;
}

string Subscribe_Request::build_packet() {
    string sub_req;
    stringstream tmp;
    tmp << this->fixed_header << this->msg_length << this->msg_id_1 << this->msg_id_2 << this->properties << this->topic_length_1 << this->topic_length_2 << this->topic << this->sub_options;
    sub_req = tmp.str();
    return sub_req;
}

void Subscribe_Request::calc_msg_length() {
    this->msg_length = sizeof(msg_id_1) + sizeof(msg_id_2) + sizeof(properties) + sizeof(topic_length_1) + sizeof(topic_length_2) + sizeof(sub_options) + (size_t)topic.size();
}

void Subscribe_Request::calc_topic_length() {
    this->topic_length_2 = static_cast<uint8_t>((size_t) topic.size());
}

void Subscribe_Request::set_all(uint8_t *buffer) {
    this->fixed_header = buffer[0];
    this->msg_length = buffer[1];
    this->msg_id_1 = buffer[2];
    this->msg_id_2 = buffer[3];
    this->properties = buffer[4];
    this->topic_length_1 = buffer[5];
    this->topic_length_2 = buffer[6];

    int i;
    for (i = 0; i < topic_length_2; i++) {
        this->topic += buffer[7+i];
    }

    this->sub_options = buffer[7+i];
}

void Subscribe_Request::set_all(uint8_t *buffer, int offset) {
    this->msg_id_1 = buffer[offset + 1];
    this->msg_id_2 = buffer[offset + 2];
    this->topic_length_1 = buffer[offset + 3];
    this->topic_length_2 = buffer[offset + 4];

    int i;
    for (i = 0; i < topic_length_2; i++) {
        this->topic += buffer[offset + 5 + i];
    }

    this->sub_options = buffer[offset + 5 + i];
}

bool Subscribe_Request::validate() {
    return this->fixed_header == 0x82 && this->sub_options <= 0x02;
}

Subscribe_Request::Subscribe_Request(uint8_t *buffer) {
    this->fixed_header = buffer[0];
    this->msg_length = buffer[1];
    this->msg_id_1 = buffer[2];
    this->msg_id_2 = buffer[3];
    this->properties = buffer[4];
    this->topic_length_1 = buffer[5];
    this->topic_length_2 = buffer[6];

    int i;
    for (i = 0; i < topic_length_2; i++) {
        this->topic += buffer[7+i];
    }

    this->sub_options = buffer[7+i];
}

Subscribe_Request::~Subscribe_Request() = default;
