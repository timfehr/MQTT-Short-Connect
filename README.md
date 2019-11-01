# MQTT Short Connect
*MQTT Short Connect* ist eine Option um die Latenz beim initialen Verbindungsaufbau von 2 *RTT* auf 1 *RTT* zu reduzieren. Dies wird erreicht durch die Kombination des *Connect*-Pakets und des *Subscribe Request*. Da beide Pakete eine gewisse Ähnlichkeit aufweisen.

Das *reserved*-Flag (Bit 0) der Connect-Flags wird verwendet als *short connect*-Flag. Bei setzen dieses signalisiert der Client dem Broker, dass er die Option des *short connects* verwenden möchte. Bei Verwendung dieser Option wird der eigentliche *Payload* des *Subscribe Request* als *Payload* hinter der Client-ID angehängt. Außerdem werden die *Properties*, welche in beiden Paketen vorkommen zusammen gefasst. Die Felder der *Total Length* und *MSG Length* müssen dem entsprechend angepasst werden. Außerdem wird das Feld *Message Identifier* in den *Header* des *Short Connect*-Paketes übernommen.

Die selbe Methode wird auch für das *Acknowledgement*-Paket benutzt. Der Vorteil hier besteht in dem sehr simplen Aufbau des Connect-Ack sowie des Subscribe-Ack. Benutzt wird in diesem Falle, die *reserved*-Flags im Connect-Ack Paket. Bit 1 wird das *short connect ack*-Flag. Wird dieses Flag vom Broker gesetzt, bestätigt er sowohl die Verbindung als auch den Subscribe-Request in einem Paket. Setzt der Broker dieses Flag nicht, obwohl der Client das *short connect*-Flag gesetzt hatte, bestätigt der Server nur den Connect. Dies bedeutet für den Client er muss zusätzlich ein eigenständiges Subscribe Request an den Server senden. Akzeptiert der Broker sowohl das Connect als auch den Subscribe Request, teilt der Broker dem Client die *granted QoS* wie bisher im Reason Code mit. Ist der Reason Code ein Wert von 0 bis 2, sind dies die gewährten *QoS*. Bei einem internen Fehler werden die bisher gültigen *Error codes* des *MQTT*-Standards verwendet. Der *Message Identiefier* und die *Properties* werden wie schon bei dem Connect-Paket zusammen gefasst. Die *Msg Length* muss auch hier dem entsprechend angepasst werden.
## Folder structure
 - TCP: MQTT Short Connect over TCP
 - DTLS: MQTT Short Connect over Datagram TLS (DTLS)
 - TLS: MQTT Short Connect over TLS 1.2 and TLS 1.3
 - QUIC: MQTT Short Connect over QUIC
 
Every subfolder has the source code and its own README with further instructions.

##CI/CD
Every subfolder has its own *.gitlab.ci*, which can be used to setup and CI/CD environment.