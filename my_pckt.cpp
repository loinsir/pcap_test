#include "my_pckt.h"
#include <stdio.h>

void print_packet_info(const u_char *pckt, unsigned int total_pckt_len){
    ETH_HDR *eth_hdr;
    eth_hdr = const_cast<ETH_HDR*>(reinterpret_cast<const ETH_HDR*>(pckt)); //cast to ethernet header
    u_short ether_type = ntohs(eth_hdr->type);           //switch byteOrder network to host

    IP_HDR *ip_hdr;
    ip_hdr = const_cast<IP_HDR*>(               //cast data to IP header
                reinterpret_cast<const IP_HDR*>
                (&pckt[eth_hdr_len]));
    int ip_hdr_len = ip_hdr->hdr_len * 4;
//    int total_pckt_len = ntohs(ip_hdr->total_len) + eth_hdr_len;
    total_pckt_len = static_cast<int>(total_pckt_len);
    TCP_HDR *tcp_hdr;
    tcp_hdr = const_cast<TCP_HDR*>(
                reinterpret_cast<const TCP_HDR*>
                (&pckt[eth_hdr_len + ip_hdr_len])); //cast data to TCP header
    uint8_t ip_type = ip_hdr->protocol;


    if (ether_type == eth_typefield_val_IP && ip_type == IP_typefield_val_TCP) {   //checking packet type
        printf("DST_MAC: ");
        print_MAC(eth_hdr->dst_MAC);

        //print source MAC address
        printf("SRC_MAC: ");
        print_MAC(eth_hdr->src_MAC);

        printf("SRC_IP: ");
        print_IP(ip_hdr->src_ip_addr);
        printf("DST_IP: ");
        print_IP(ip_hdr->dst_ip_addr);

        printf("Total len: ");
        printf("%d\n", total_pckt_len);

        printf("SRC_PORT: %d\nDST_PORT: %d\n", ntohs(tcp_hdr->src_port), ntohs(tcp_hdr->dst_port));

        int pckt_data_idx = eth_hdr_len + ip_hdr_len + (tcp_hdr->offset) * 4;
        printf("total_hdr_len: ");
        printf("%d\n", pckt_data_idx);

        printf("TCP DATA(maximum 10byte): ");
        print_DATA(&pckt[pckt_data_idx], total_pckt_len - pckt_data_idx);
    }
}

void print_MAC(const u_char *data){
    for (int i = 0; i < 6; i++) {
        printf("%02X", data[i]);
        (i != 5) ? printf(":") : printf("\n");   //Seperate MAC ADDRESS
    }
}

void print_IP(const u_char *data){
    for (int i = 0; i < 4; i++) {
        printf("%d", data[i]);
        (i != 3) ? printf(".") : printf("\n");
    }
}

void print_DATA(const u_char *data, int data_len){
    for (int idx = 0 ; idx < data_len && idx < 10 ; idx++) {
        printf("%02X ", data[idx]);
    }
    printf("\n");
}
