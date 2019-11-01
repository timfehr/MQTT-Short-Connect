## Transportprotokoll
Used transport protocol is UDP with TLS 1.2 (DTLS).

## Prerequisite
 - Linux Kernel > 3.7
 - [OpenSSL](https://www.openssl.org/source/) in Version 1.1.1

## Installation
*MQTT Short Connect* uses `cmake` as *build system*.
```bash
    mkdir build
    cd build
    cmake ..
    make
```
Create the certificate and key used by the server
```bash
    openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem
```
## Config
To adjust your config, just edit the config.env. Please be careful, this file is case sensitiv. Please do not change to layout of this file!
## Run
Server
```bash
    ./MQTT_Server
```
Client
```bash
    ./MQTT_Client
```

The TLS secrets will be saved in *tls_keys.log*. This file can be used to decrypt the traffic.
## Example
Wireshark captures can be found in the subfolder captures. One for the initial session establishment and one for the resumption.
## Know issues
 - Wireshark is not detecting MQTT in the captures. It just shows *Application Data*
 - Session resumption is not working with *DTLS* because it isn't part of the protocol.