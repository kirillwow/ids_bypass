#include "server.h"

#define DATA "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 21\r\n\r\nyou have been hacked!"

pcap_t* pd;
int sock = 0, one = 1;
int sender_port = 0;
int debug_output = 0;
int send_ack = 0;

void parse_packet(u_char *user, struct pcap_pkthdr *packethdr, 
                  u_char *packetptr)
{
    struct ip* iphdr;
    struct tcphdr* tcphdr;
    char iphdrInfo[256], srcip[256], dstip[256];
        
    int bytes;
    struct iphdr *ipHdr;
    struct tcphdr *tcpHdr;
    char *data;
    char synack_packet[2048];
    char pshack_packet[2048];
    char finack_packet[2048];
    char ack_packet[2048];
    struct sockaddr_in addr_in;
    int seq_number;
 
    // Skip the datalink layer header and get the IP header fields.
    packetptr += linkhdrlen;
    iphdr = (struct ip*)packetptr;
    strcpy(srcip, inet_ntoa(iphdr->ip_src));
    strcpy(dstip, inet_ntoa(iphdr->ip_dst));
    sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
            ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
            4*iphdr->ip_hl, ntohs(iphdr->ip_len));
 
    // Advance to the transport layer header then parse and display
    // the fields based on the type of hearder: tcp, udp or icmp.
    packetptr += 4*iphdr->ip_hl;
    if (iphdr->ip_p == IPPROTO_TCP )
    {
        tcphdr = (struct tcphdr*)packetptr;
            
        addr_in.sin_family = AF_INET;
        addr_in.sin_port = tcphdr->source;
        addr_in.sin_addr.s_addr = iphdr->ip_src.s_addr;
        
        if (debug_output)
        {
            printf("[*] TCP  %s:%d -> %s:%d\t", srcip, ntohs(tcphdr->source), dstip, ntohs(tcphdr->dest));
            printf( "%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
                (tcphdr->urg ? 'U' : '*'), (tcphdr->ack ? 'A' : '*'),
                (tcphdr->psh ? 'P' : '*'), (tcphdr->rst ? 'R' : '*'),
                (tcphdr->syn ? 'S' : '*'), (tcphdr->fin ? 'F' : '*'),
                ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq), ntohs(tcphdr->window), 4*tcphdr->doff
            );
        }
        
        sender_port = ntohs(tcphdr->source);
        seq_number = rand();

        memset(synack_packet, 0, sizeof(synack_packet));
        memset(pshack_packet, 0, sizeof(pshack_packet));
        memset(finack_packet, 0, sizeof(finack_packet));
        memset(ack_packet, 0, sizeof(ack_packet));
        
        // Preparing SYN-ACK packet
        ipHdr = (struct iphdr *) synack_packet;
        tcpHdr = (struct tcphdr *) (synack_packet + sizeof(struct iphdr));

        ipHdr->ihl = 5;
        ipHdr->version = 4;
        ipHdr->tos = 0;
        ipHdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        ipHdr->id = htons(rand());
        ipHdr->frag_off = 0x00; 
        ipHdr->ttl = 0xFF;
        ipHdr->protocol = IPPROTO_TCP;
        ipHdr->check = 0;
        ipHdr->saddr = iphdr->ip_dst.s_addr;
        ipHdr->daddr = iphdr->ip_src.s_addr;

        ipHdr->check = csum((unsigned short *) synack_packet, ipHdr->tot_len); 

        tcpHdr->source = tcphdr->dest; 
        tcpHdr->dest = tcphdr->source;
        tcpHdr->seq = htonl(seq_number);
        seq_number += 1; // Increment seq number
        tcpHdr->ack_seq = htonl(ntohl(tcphdr->seq) + 1);
        tcpHdr->doff = 5;
        tcpHdr->res1 = 0;
        tcpHdr->cwr = 0; 
        tcpHdr->ece = 0;
        tcpHdr->urg = 0;
        tcpHdr->ack = 1; 
        tcpHdr->psh = 0;
        tcpHdr->rst = 0;
        tcpHdr->syn = 1;
        tcpHdr->fin = 0; 
        tcpHdr->window = htons(15500);
        tcpHdr->check = 0; 
        tcpHdr->urg_ptr = 0;
        tcpHdr->check = tcp_checksum(tcpHdr, sizeof(struct tcphdr), iphdr->ip_dst.s_addr, iphdr->ip_src.s_addr);
            
        // Preparing DATA packet
        memcpy(pshack_packet, synack_packet, sizeof(struct iphdr) + sizeof(struct tcphdr));
        ipHdr = (struct iphdr *) pshack_packet;
        tcpHdr = (struct tcphdr *) (pshack_packet + sizeof(struct iphdr));
        data = (char *) (pshack_packet + sizeof(struct iphdr) + sizeof(struct tcphdr));
        strcpy(data, DATA);
        ipHdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data);
        tcpHdr->seq = htonl(seq_number);
        seq_number += strlen(data);// Increment seq number
        tcpHdr->syn = 0;
        tcpHdr->psh = 1;
        tcpHdr->check = 0x0;
        tcpHdr->check = tcp_checksum(tcpHdr, sizeof(struct tcphdr) + strlen(data), iphdr->ip_dst.s_addr, iphdr->ip_src.s_addr);
            
        // Preparing FIN packet
        memcpy(finack_packet, pshack_packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data));
        ipHdr = (struct iphdr *) finack_packet;
        tcpHdr = (struct tcphdr *) (finack_packet + sizeof(struct iphdr));
        tcpHdr->seq = htonl(seq_number);
        seq_number += 1; // Increment seq number
        ipHdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        tcpHdr->fin = 1;
        tcpHdr->psh = 0;
        tcpHdr->check = 0x0;
        tcpHdr->check = tcp_checksum(tcpHdr, sizeof(struct tcphdr), iphdr->ip_dst.s_addr, iphdr->ip_src.s_addr);
        
        // Preparing ACK packet
        memcpy(ack_packet, synack_packet, sizeof(struct iphdr) + sizeof(struct tcphdr));
        ipHdr = (struct iphdr *) ack_packet;
        tcpHdr = (struct tcphdr *) (ack_packet + sizeof(struct iphdr));
        tcpHdr->seq = tcphdr->ack_seq;
        tcpHdr->ack_seq = htonl(ntohl(tcphdr->seq) + 1);
        if (strlen((char*) tcphdr + 4*tcphdr->doff) > 0)
            tcpHdr->ack_seq = htonl(ntohl(tcpHdr->ack_seq) - 1 + strlen((char*) tcphdr + 4*tcphdr->doff));
        ipHdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        tcpHdr->ack = 1; 
        tcpHdr->psh = 0;
        tcpHdr->rst = 0;
        tcpHdr->syn = 0;
        tcpHdr->fin = 0; 
        tcpHdr->check = 0x0;
        tcpHdr->check = tcp_checksum(tcpHdr, sizeof(struct tcphdr), iphdr->ip_dst.s_addr, iphdr->ip_src.s_addr);
        
        if (tcphdr->syn && !tcphdr->ack )
        {
            printf("[+] Incoming connection from <%s:%d>\n\t", srcip, ntohs(tcphdr->source));
            ipHdr = (struct iphdr *) synack_packet;            
            if((bytes = sendto(sock, synack_packet, ipHdr->tot_len, 0, (struct sockaddr *) &addr_in, sizeof(addr_in))) < 0)
                perror("Error on sendto()");
            else {
                printf("[+] [%s:%d] Sending SYN-ACK\n", srcip, ntohs(tcphdr->source));
            }
            ipHdr = (struct iphdr *) pshack_packet;            
            if((bytes = sendto(sock, pshack_packet, ipHdr->tot_len, 0, (struct sockaddr *) &addr_in, sizeof(addr_in))) < 0)
                perror("Error on sendto()");
            else {
                printf("\t[+] [%s:%d] Sending HTTP response data\n", srcip, ntohs(tcphdr->source));
            }
            ipHdr = (struct iphdr *) finack_packet;            
            if((bytes = sendto(sock, finack_packet, ipHdr->tot_len, 0, (struct sockaddr *) &addr_in, sizeof(addr_in))) < 0)
                perror("Error on sendto()");
            else {
                printf("\t[+] [%s:%d] Closing connection. Sending FIN-ACK\n", srcip, ntohs(tcphdr->source));
            }
        }
        else if (tcphdr->ack && (tcphdr->psh || tcphdr->fin) && send_ack)
        {            
            ipHdr = (struct iphdr *) ack_packet;
            if((bytes = sendto(sock, ack_packet, ipHdr->tot_len, 0, (struct sockaddr *) &addr_in, sizeof(addr_in))) < 0)
                perror("Error on sendto()");
            else
                printf("[+] ACKing to [%s:%d]\n", srcip, ntohs(tcphdr->source));
        }
    }
}


int main(int argc, char **argv)
{
    char help[256] = "";
    char interface[256] = "", bpfstr[256] = "", port[256] = "";
    int c;
    
    sprintf(help, "usage: %s -i <interface> -p <port: 1..65535> [-d] [-a]\n\t-d\tenable debug output\n\t-a\tsend ACK packet to every incoming data packet\n\n", argv[0]);
    
    if((sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("Error while creating socket");
        exit(-1);
    }

    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one)) < 0) {
        perror("Error while setting socket options");
        exit(-1);
    }
    
    while ((c = getopt (argc, argv, "hadi:p:")) != -1)
    {
        switch (c)
        {
        case 'i':
            strcpy(interface, optarg);
            break;
        case 'p':
            strcpy(port, optarg);
            break;
        case 'd':
            debug_output = 1;
            break;
        case 'a':
            send_ack = 1;
            break;
        case 'h':
        default:
            printf("%s", help);
            exit(0);
            break;
        }
    }
    
    if (atoi(port) < 1 || atoi(port) > 65535 || interface[0] == 0x0)
    {
        printf("%s", help);
        exit(0);
    }
    
    strcat(bpfstr, "tcp and dst port ");
    strcat(bpfstr, port);
    
    if ((pd = open_pcap_socket(interface, bpfstr)))
    {
        capture_loop(pd, 0, (pcap_handler)parse_packet);
    }
    exit(0);
}
