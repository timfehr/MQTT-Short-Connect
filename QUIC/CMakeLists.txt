cmake_minimum_required(VERSION 3.13cmake)
project(MQTT_Server)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_REQUIRED_LINK_OPTIONS -L/usr/local/lib)
set(LIB ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})

include_directories(AFTER SYSTEM /usr/local/include)
link_directories(AFTER /usr/local/lib)

list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES ${LIB} isSystemDir)
if("${isSystemDir}" STREQUAL "-1")
    set(CMAKE_INSTALL_RPATH ${LIB})
endif()


if(APPLE AND NOT IPO)
    find_program(DSYMUTIL dsymutil)
endif()

add_subdirectory(external)
add_subdirectory(deps)

if (UNIX AND NOT APPLE)
    find_library(CRYPTO_LIB libcrypto.so.1.1)
    find_library(SSL_LIB libssl.so.1.1)
    find_library(QUANT libquant.a)
    find_library(SOCK libsockcore.a)
    #find_library(PICOQUIC picoquic-core)
    #find_library(PTLSMINI picotls-minicrypto)
    #find_library(PTLSSSL picotls-openssl)
    #find_library(PTLSCORE picotls-core)
else()
    find_library(CRYPTO_LIB libcrypto.1.1.dylib)
    find_library(SSL_LIB libssl.1.1.dylib)
    find_library(QUANT libquant.a)
    find_library(SOCK libsockcore.a)
    #find_library(PICOQUIC picoquic-core)
    #find_library(PTLSMINI picotls-minicrypto)
    #find_library(PTLSSSL picotls-openssl)
    #find_library(PTLSCORE picotls-core)
endif ()

add_executable(MQTT_Server mqtt_server.cpp Classes/Packet.cpp Classes/Packet.h Classes/Connect_Packet.cpp Classes/Connect_Packet.h Classes/Subscribe_Ack.cpp Classes/Subscribe_Ack.h Classes/Connect_Ack.cpp Classes/Connect_Ack.h Classes/Subscribe_Request.cpp Classes/Subscribe_Request.h Classes/Short_Connect.cpp Classes/Short_Connect.h Classes/Short_Ack.cpp Classes/Short_Ack.h)
add_executable(MQTT_Client mqtt_client.cpp Classes/Packet.cpp Classes/Packet.h Classes/Connect_Packet.cpp Classes/Connect_Packet.h Classes/Subscribe_Ack.cpp Classes/Subscribe_Ack.h Classes/Connect_Ack.cpp Classes/Connect_Ack.h Classes/Subscribe_Request.cpp Classes/Subscribe_Request.h Classes/Short_Connect.cpp Classes/Short_Connect.h Classes/Short_Ack.cpp Classes/Short_Ack.h)
target_link_libraries(MQTT_Server ${CRYPTO_LIB} ${SSL_LIB} ${QUANT} ${SOCK} picohttp-core picoquic-core picotls-minicrypto picotls-openssl)
target_link_libraries(MQTT_Client ${CRYPTO_LIB} ${SSL_LIB} ${QUANT} ${SOCK} picohttp-core picoquic-core picotls-minicrypto picotls-openssl)

target_include_directories(MQTT_Server
        SYSTEM PRIVATE
        ${HTTP_PARSER_INCLUDE}
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/deps/picoquic>
        )

target_include_directories(MQTT_Client
        SYSTEM PRIVATE
        ${HTTP_PARSER_INCLUDE}
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/deps/picoquic>
        )