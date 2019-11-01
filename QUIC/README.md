[![pipeline status](https://git.uniberg.com/tim.fehr/mqtt-short-connect/badges/MQTT_Short_Connect_QUANT/pipeline.svg)](https://git.uniberg.com/tim.fehr/mqtt-short-connect/commits/MQTT_Short_Connect_QUANT)

# MQTT Short Connect
MQTT Short Connect ist eine zusammenführung des Connect Packetes und des Subscribe Packetes. Damit wird die Latenz während des initialen Verbindungsaufbaus um 1 RTT gesenkt. Dieses Repo enthält diese Idee als eine Art *Proof of Concept* über verschiedne Transportprotokolle. Die hier eingesetzten Protokolle sind *TCP* mit der *Fast Open (TFO)* Funktion. *TCP* mit *TLS* in Versionen 1.2 und 1.3 und *QUIC*.

Die Implementierung dient der Messung der *Round Trip Times* bei einem intialen Verbindungsaufbau und einen Wiederaufbau einer früheren Verbindung.

Das Repo ist so aufgebaut, dass die jeweilige *MQTT Short Implementierung* in den einzelenen Branches, aufgeteilt auf die jeweiligen Transportprotokolle liegen. Jede branch enthält sowohl einen Client als auch einen Server. Die Konfiguration erfeolgt jeweils über eine *config* Datei. In der Datei "config.env" können alle Einstellungen wie die IP, der Port, die Client-ID und das Topic mit den gewünschten QoS vergenommen werden. **ACHTUNG**: Die Datei ist _case-sensitiv_. Es dürfen keine Leerzeichen in den Zeilen vorkommen!


Außerdem enthält jeder Branch *Wiresahrk captures* in denen der Verbindungsaufbau und Wiederaufbau nachvollzogen werden kann. Die *captures* sind als *.pcap* vorhanden und wurden mit Hilfe der hier enthalten Programme erzeugt.

## Transprtprotokoll
Als Transportprotokoll kommt [*QUIC*](https://quicwg.org), welches sich zur Zeit im im Standartisierungsprozess der *IETF* befindet. *QUIC* baut auf *UDP* auf und verbindet dieses mit Optionen von *TCP*, zum Beispiel einer *Congestion Control*. Als Bibliothek zur Implementierung wird [*QUANT*](https://github.com/NTAP/quant) verwendet.

## Prerequisite
 - QUANT

 ## Installation
 *MQTT Short Connect* nutzt als *build system* `cmake`.
```bash
    git submodule update --init --recursive
    mkdir build
    cd build
    cmake ..
    make
```
Die Programm liegen dann im Ordner *build*.