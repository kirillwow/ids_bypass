#ifndef SERVER_H
#define SERVER_H

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <netdb.h> 
#include <sys/types.h>
#define __FAVOR_BSD
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <net/if.h>

#include <errno.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

int linkhdrlen;

uint16_t udp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr)
{
    const uint16_t *buf=buff;
    uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
    uint32_t sum = 0;
 
    sum += htons(IPPROTO_UDP);
    sum += htons(len);
    sum += *(ip_src++);
    sum += *ip_src; 
    sum += *(ip_dst++);
    sum += *ip_dst;
    
    for (; len > 1; len -=2)
        sum += *buf++;
 
    if ( len & 1 )
        sum += *((uint8_t *)buf);
 
    sum = (sum & 0xFFFF) + (sum >> 16);
 
    return ( (uint16_t)(~sum)  );
}

uint16_t tcp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr)
{
    const uint16_t *buf=buff;
    uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
    uint32_t sum = 0;
 
    sum += htons(IPPROTO_TCP);
    sum += htons(len);
    sum += *(ip_src++);
    sum += *ip_src; 
    sum += *(ip_dst++);
    sum += *ip_dst;
    
    for (; len > 1; len -=2)
        sum += *buf++;
 
    if ( len & 1 )
        sum += *((uint8_t *)buf);
 
    sum = (sum & 0xFFFF) + (sum >> 16);
 
    return ( (uint16_t)(~sum)  );
}

unsigned short csum(unsigned short *ptr,int nbytes) {
    unsigned long sum;

    sum = 0;
    for (; nbytes > 1; nbytes -= 2)
        sum += *ptr++;
    
    if(nbytes == 1)
        sum+=*(u_char*)ptr;

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);

    return (short) ~sum;;
}

pcap_t* open_pcap_socket(char* device, const char* bpfstr)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pd;
    uint32_t  srcip, netmask;
    struct bpf_program  bpf;

    // If no network interface (device) is specfied, get the first one.
    if (!*device && !(device = pcap_lookupdev(errbuf)))
    {
        printf("pcap_lookupdev(): %s\n", errbuf);
        return NULL;
    }
    
    // Open the device for live capture, as opposed to reading a packet
    // capture file.
    if ((pd = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL)
    {
        printf("pcap_open_live(): %s\n", errbuf);
        return NULL;
    }

    // Get network device source IP address and netmask.
    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) < 0)
    {
        printf("pcap_lookupnet: %s\n", errbuf);
        return NULL;
    }

    // Convert the packet filter epxression into a packet
    // filter binary.
    if (pcap_compile(pd, &bpf, (char*)bpfstr, 0, netmask))
    {
        printf("pcap_compile(): %s\n", pcap_geterr(pd));
        return NULL;
    }

    // Assign the packet filter to the given libpcap socket.
    if (pcap_setfilter(pd, &bpf) < 0)
    {
        printf("pcap_setfilter(): %s\n", pcap_geterr(pd));
        return NULL;
    }

    return pd;
}

void capture_loop(pcap_t* pd, int packets, pcap_handler func)
{
    int linktype;
 
    // Determine the datalink layer type.
    if ((linktype = pcap_datalink(pd)) < 0)
    {
        printf("pcap_datalink(): %s\n", pcap_geterr(pd));
        return;
    }
 
    // Set the datalink layer header size.
    switch (linktype)
    {
    case DLT_NULL:
        linkhdrlen = 4;
        break;
 
    case DLT_EN10MB:
        linkhdrlen = 14;
        break;
 
    case DLT_SLIP:
    case DLT_PPP:
        linkhdrlen = 24;
        break;
 
    default:
        printf("Unsupported datalink (%d)\n", linktype);
        return;
    }
 
    // Start capturing packets.
    if (pcap_loop(pd, packets, func, 0) < 0)
        printf("pcap_loop failed: %s\n", pcap_geterr(pd));
}

#endif