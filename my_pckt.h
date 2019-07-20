#pragma once
#include <arpa/inet.h>

#define eth_hdr_len 14
#define eth_typefield_val_IP 0x0800
#define IP_typefield_val_TCP 0x06
#define default_tcp_hdr_len 20

struct ETH_HDR {
    u_char dst_MAC[6];         //6byte
    u_char src_MAC[6];         //6byte
    u_short type;              //2byte
};

struct IP_HDR {
    u_char hdr_len :4;            //     using bit field
    u_char Version :4;
    u_char TOS;
    u_short total_len;
    u_short id;
    u_short flag :3;
    u_short frag_offset :13;
    u_char TTL;
    u_char protocol;
    u_short hdr_checksum;
    u_char src_ip_addr[4];
    u_char dst_ip_addr[4];
};

struct TCP_HDR {
    u_short src_port;
    u_short dst_port;
    u_int32_t seqNO;
    u_int32_t ackNO;
    u_char reserved :4;
    u_char offset :4;
    u_char flags;
    u_short window_size;
    u_short checksum;
    u_short urgent_ptr;
};

void print_packet_info(const u_char *pckt, unsigned int total_pckt_len);
void print_MAC(const u_char *data);
void print_IP(const u_char *data);
void print_port(const u_char *data);
void print_DATA(const u_char *data, int data_len);
