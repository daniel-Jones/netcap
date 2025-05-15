/*
    Daniel Jones
    GNU GPLv3 license, see LICENSE for more details
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/udp.h>

// helper macros
// ---------------------
#define VERBOSE_PRINTF(...) \
    do { \
        if (verbose) { \
            printf(__VA_ARGS__); \
        } \
    } while (0)

// we want to print the hexdump to stdout and optionally to a file
#define PRINT_HEX_ASCII(data, size) \
    do { \
        print_hex_ascii(stdout, data, size); \
        if (out_handle) print_hex_ascii(out_handle, data, size); \
    } while (0)
// ---------------------

int num_packets  =      0;    // default to infinite packets
int port         =      0;    // default to all ports
char *interface  =   NULL;    // default to all interfaces
bool verbose     =  false;    // default to no verbose output
char *out_file   =   NULL;    // default to no output file
FILE *out_handle =   NULL;    

void usage(FILE *file, char *argv[]);
void print_hex_ascii(FILE *file, const unsigned char *data, size_t size);
void capture_packets(void);
void print_eth_header(const struct ethhdr *eth, uint16_t eth_type, bool vlan_present, uint16_t vlan_id);
void print_ip_header(const struct iphdr *ip, size_t iphdrlen, uint8_t protocol);
void print_tcp_header(const struct tcphdr *tcp);
void print_udp_header(const struct udphdr *udp);

void
usage(FILE *file, char *argv[])
{
    fprintf(file, "Usage: %s [-h] [-v] [-n packets] [-i interface] [-p port] [-o out_file]\n", argv[0]);
}

bool
has_raw_socket_permission(void)
{
    /*
        to open a raw socket we either need root or the cap_net_raw capability set on the binary
        this returns false if we don't have the capability
    */
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0)
    {
        if (errno == EPERM || errno == EACCES)
        {
            return false;
        } else
        {
            perror("socket");
            return false;
        }
    }
    close(sockfd);
    return true;
}

void
print_eth_header(const struct ethhdr *eth, uint16_t eth_type, bool vlan_present, uint16_t vlan_id)
{
    VERBOSE_PRINTF("Ethernet Header:\n");
    VERBOSE_PRINTF("  Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->h_source[0], eth->h_source[1], eth->h_source[2],
        eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    VERBOSE_PRINTF("  Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
        eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    VERBOSE_PRINTF("  EtherType: 0x%04x\n", eth_type);
    if (vlan_present)
    {
        VERBOSE_PRINTF("  VLAN tag present: VLAN ID %u\n", vlan_id);
    }
}

void
print_ip_header(const struct iphdr *ip, size_t iphdrlen, uint8_t protocol)
{
    VERBOSE_PRINTF("IP Header:\n");
    VERBOSE_PRINTF("  Src IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
    VERBOSE_PRINTF("  Dst IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));
    if (protocol == IPPROTO_TCP)
        VERBOSE_PRINTF("  Protocol: %u (TCP)\n", ip->protocol);
    else if (protocol == IPPROTO_UDP)
        VERBOSE_PRINTF("  Protocol: %u (UDP)\n", ip->protocol);
    else
        VERBOSE_PRINTF("  Protocol: %u\n", ip->protocol);
    VERBOSE_PRINTF("  Header Length: %zu\n", iphdrlen);
    VERBOSE_PRINTF("  Total Length: %u\n", ntohs(ip->tot_len));
}

void
print_tcp_header(const struct tcphdr *tcp)
{
    VERBOSE_PRINTF("TCP Header:\n");
    VERBOSE_PRINTF("  Src Port: %u\n", ntohs(tcp->source));
    VERBOSE_PRINTF("  Dst Port: %u\n", ntohs(tcp->dest));
    VERBOSE_PRINTF("  Seq: %u\n", ntohl(tcp->seq));
    VERBOSE_PRINTF("  Ack: %u\n", ntohl(tcp->ack_seq));
    VERBOSE_PRINTF("  Data Offset: %u\n", tcp->doff * 4);
    VERBOSE_PRINTF("  Flags: 0x%02x\n", ((unsigned char *)tcp)[13]);
}

void
print_udp_header(const struct udphdr *udp)
{
    VERBOSE_PRINTF("UDP Header:\n");
    VERBOSE_PRINTF("  Src Port: %u\n", ntohs(udp->source));
    VERBOSE_PRINTF("  Dst Port: %u\n", ntohs(udp->dest));
    VERBOSE_PRINTF("  Length: %u\n", ntohs(udp->len));
    VERBOSE_PRINTF("  Checksum: 0x%04x\n", ntohs(udp->check));
}

void
capture_packets(void)
{
    int sockfd;
    char frame[65536];
    struct ifreq ifr;
    struct sockaddr_ll sll;
    size_t packet_count = 0;

    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // bind to our selected interface
    if (interface)
    {
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
        if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1)
        {
            perror("Cannot bind to interface");
            close(sockfd);
            exit(EXIT_FAILURE);
        }
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifr.ifr_ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);
        if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) == -1)
        {
            perror("Cannot bind to interface");
            close(sockfd);
            exit(EXIT_FAILURE);
        }
    }

    VERBOSE_PRINTF("Capturing TCP/UDP packets on interface: %s, port: %d\n", interface ? interface : "all", port);

    while (num_packets == 0 || packet_count < num_packets)
    {
        ssize_t frame_size = recvfrom(sockfd, frame, sizeof(frame), 0, NULL, NULL);
        if (frame_size < 0)
        {
            perror("recvfrom");
            break;
        }

        // layer 2 headers 
        struct ethhdr *eth = (struct ethhdr *)frame; // ethernet headers
        uint16_t eth_type = ntohs(eth->h_proto); // ethernet type
        bool vlan_present = false; // vlan tag present
        uint16_t vlan_id = 0; // vlan id
        size_t l2_offset = sizeof(struct ethhdr); // offset to the end of the ethernet header aka the start of the level 3 ip header
        // check frame for VLAN extension tag
        if (eth_type == 0x8100)
        {
            vlan_present = true;
            const unsigned char *vlan_ptr = frame + sizeof(struct ethhdr); // vlan tag right after eth header
            uint16_t tci = (vlan_ptr[0] << 8) | vlan_ptr[1];
            /*
                tci is the first two bytes of the vlan tag
                the last 12 bits are the vlan id
                the first 4 bits are the priority and cfi bits
            */
            vlan_id = tci & 0x0FFF;
            eth_type = (vlan_ptr[2] << 8) | vlan_ptr[3]; // eth type is the last two bytes of the vlan tag
            l2_offset += 4; // skip the vlan tag for the next layer 3 header
        }
        if (eth_type != ETH_P_IP)
            continue; // not an IP packet
        // layer 3 headers
        struct iphdr *ip = (struct iphdr *)(frame + l2_offset);
        size_t iphdrlen = ip->ihl * 4; // ihl is the internet header length in 32-bit words, *4 to get bytes

        if (ip->protocol == IPPROTO_TCP)
        {
            struct tcphdr *tcp = (struct tcphdr *)(frame + l2_offset + iphdrlen);
            /*
                filter by port if specificed
                if neither source or destination port match our specific port, we just skip the packet
                (make sure we are either an incoming or outgoing packet)
            */
            if (port > 0 && ntohs(tcp->source) != port && ntohs(tcp->dest) != port)
                continue;
            /*
                payload is the data after the tcp header
                tcp header tcp->doff is 32 bit words, *4 to get bytes

                ip header address + ip header length + tcp header length
            */
            size_t tcp_offset = l2_offset + iphdrlen + tcp->doff * 4;
            size_t payload_len = ntohs(ip->tot_len) - iphdrlen - tcp->doff * 4;
            const unsigned char *payload = (const unsigned char *)(frame + tcp_offset); // we may want to print only the payload at some point?

            VERBOSE_PRINTF("\n=== Packet %zu ===\n", packet_count + 1);
            print_eth_header(eth, eth_type, vlan_present, vlan_id);
            print_ip_header(ip, iphdrlen, ip->protocol);
            print_tcp_header(tcp);
            VERBOSE_PRINTF("\nFull Packet Hexdump:\n");
            PRINT_HEX_ASCII((const unsigned char *)frame, frame_size);
            VERBOSE_PRINTF("---\n");
            packet_count++;
        }
        else if (ip->protocol == IPPROTO_UDP)
        {
            struct udphdr *udp = (struct udphdr *)(frame + l2_offset + iphdrlen);
            /*
                filter by port if specificed
                if neither source or destination port match our specific port, we just skip the packet
                (make sure we are either an incoming or outgoing packet)
            */
            if (port > 0 && ntohs(udp->source) != port && ntohs(udp->dest) != port)
                continue;
            /*
                payload is the data after the udp header
                udp header is always 8 bytes
            */
            size_t udp_offset = l2_offset + iphdrlen + sizeof(struct udphdr);
            size_t payload_len = ntohs(udp->len) - sizeof(struct udphdr);
            const unsigned char *payload = (const unsigned char *)(frame + udp_offset);

            VERBOSE_PRINTF("\n=== Packet %zu ===\n", packet_count + 1);
            print_eth_header(eth, eth_type, vlan_present, vlan_id);
            print_ip_header(ip, iphdrlen, ip->protocol);
            print_udp_header(udp);
            VERBOSE_PRINTF("\nFull Packet Hexdump:\n");
            PRINT_HEX_ASCII((const unsigned char *)frame, frame_size);
            VERBOSE_PRINTF("---\n");
            packet_count++;
        }
    }
    close(sockfd);
}

int
main(int argc, char *argv[])
{
    int opt;
    
    while ((opt = getopt(argc, argv, "hvn:i:p:o:")) != -1)
    {
        switch (opt)
        {
            case 'h':
                usage(stdout, argv);
                printf("Options:\n");
                printf("  -h    Show this help message\n");
                printf("  -v    Verbose output\n");
                printf("  -n    Number of packets to process (default: 0 (infinite))\n");
                printf("  -i    Interface to listen on (default: all interfaces)\n");
                printf("  -p    Port number to listen to (default: any)\n");
                printf("  -o    Output file (default: no output file)\n");
                return EXIT_SUCCESS;

            case 'n':
                num_packets = atoi(optarg);
                if (num_packets <= 0)
                {
                    fprintf(stderr, "Error: Number of packets must be positive\n");
                    return EXIT_FAILURE;
                }
                break;

            case 'p':
                port = atoi(optarg);
                if (port <= 0)
                {
                    fprintf(stderr, "Error: Port number must be positive\n");
                    return EXIT_FAILURE;
                }
                break;

            case 'i':
                interface = optarg;
                break;

            case 'v':
                verbose = true;
                break;

            case 'o':
                out_file = optarg;
                break;

            default:
                usage(stderr, argv);
                return EXIT_FAILURE;
        }
    }

    // make sure we have permission to use a raw socket
    if (!has_raw_socket_permission())
    {
        fprintf(stderr, "Error: Insufficient permissions.\n");
        fprintf(stderr, "Run as root or grant permissions with:\n");
        fprintf(stderr, "  sudo setcap cap_net_raw+ep %s\n", argv[0]);
        return EXIT_FAILURE;
    }

    VERBOSE_PRINTF("num_packets: %d\n", num_packets);
    VERBOSE_PRINTF("port: %d\n", port);
    VERBOSE_PRINTF("interface: %s\n", interface ? interface : "all");
    VERBOSE_PRINTF("out_file: %s\n", out_file ? out_file : "no output file");


    if (out_file)
    {
        out_handle = fopen(out_file, "w");
        if (!out_handle)
            perror("Cannot open output file"); 
    }

    capture_packets(); // capture packets

    if (out_handle)
        fclose(out_handle);

    return EXIT_SUCCESS;
}

void
print_hex_ascii(FILE *file, const unsigned char *data, size_t size)
{
    /*
        Print the hex and ascii in the style of a hexdump
    */
    for (size_t i = 0; i < size; i += 16)
    {
        // offset
        fprintf(file, "%04x  ", (unsigned int)i);
        // hex values
        for (size_t j = 0; j < 16 && i + j < size; j++)
        {
            fprintf(file, "%02x ", data[i + j]);
        }
        // pad if less than 16 bytes
        for (size_t j = size - i; j < 16; j++) fprintf(file, "   ");
        fprintf(file, " ");
        // ascii
        for (size_t j = 0; j < 16 && i + j < size; j++)
        {
            unsigned char c = data[i + j];
            fprintf(file, "%c", isprint(c) ? c : '.');
        }
        fprintf(file, "\n");
    }
}