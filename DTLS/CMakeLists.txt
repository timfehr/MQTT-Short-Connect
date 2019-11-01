cmake_minimum_required(VERSION 3.13cmake)
project(MQTT_Server)

set(CMAKE_CXX_STANDARD 17)

include_directories(/usr/local/include)

if (UNIX AND NOT APPLE)
    find_library(CRYPTO_LIB libcrypto.so.1.1)
    find_library(SSL_LIB libssl.so.1.1)
else()
    find_library(CRYPTO_LIB libcrypto.1.1.dylib)
    find_library(SSL_LIB libssl.1.1.dylib)
endif ()

add_executable(MQTT_Server mqtt_server.cpp Classes/Packet.cpp Classes/Packet.h Classes/Connect_Packet.cpp Classes/Connect_Packet.h Classes/Subscribe_Ack.cpp Classes/Subscribe_Ack.h Classes/Connect_Ack.cpp Classes/Connect_Ack.h Classes/Subscribe_Request.cpp Classes/Subscribe_Request.h Classes/Short_Connect.cpp Classes/Short_Connect.h Classes/Short_Ack.cpp Classes/Short_Ack.h)
add_executable(MQTT_Client mqtt_client.cpp Classes/Packet.cpp Classes/Packet.h Classes/Connect_Packet.cpp Classes/Connect_Packet.h Classes/Subscribe_Ack.cpp Classes/Subscribe_Ack.h Classes/Connect_Ack.cpp Classes/Connect_Ack.h Classes/Subscribe_Request.cpp Classes/Subscribe_Request.h Classes/Short_Connect.cpp Classes/Short_Connect.h Classes/Short_Ack.cpp Classes/Short_Ack.h)
target_link_libraries(MQTT_Server ${CRYPTO_LIB} ${SSL_LIB})
target_link_libraries(MQTT_Client ${CRYPTO_LIB} ${SSL_LIB})