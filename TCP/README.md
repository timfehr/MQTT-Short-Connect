[![pipeline status](https://git.uniberg.com/tim.fehr/mqtt-short-connect/badges/MQTT_Short_Connect_TCP/pipeline.svg)](https://git.uniberg.com/tim.fehr/mqtt-short-connect/commits/MQTT_Short_Connect_TCP)
## MQTT Short Connect over TCP
Used transport protocol is TCP with the Fast Open (TFO) option (if availible). To get an overview about TFO anf how you enable it for linux have a look [here](https://www.keycdn.com/support/tcp-fast-open).

## Prerequisite
 - Linux Kernel > 3.7

## Installation
*MQTT Short Connect* nutzt als *build system* `cmake`.
```bash
    mkdir build
    cd build
    cmake ..
    make
```
## Config
To adjust your config, just edit the *config.env*. Please be careful, this file is case sensitiv. Please do not change to layout of this file!

## Run
Server
```bash
    ./MQTT_Server
```

Client
```bash
    ./MQTT_Client
```

## Example captures
Wireshark captures can be found in the subfolder *captures*. One for the initial session establishment and one for the resumption.