#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <my_pckt.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
//  if (argc != 2) {             // Check argument.
//    usage();
//    return -1;
//  }

//  char* dev = argv[1];         // device name
  char* dev = "ens33";
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    printf("==============================================\n");
    print_packet_info(packet);                     //print packet information
    printf("==============================================\n");
  }

  pcap_close(handle);
  return 0;
}

void print_packet_info(const u_char *pckt){
    ETH_HDR *eth_hdr;
    eth_hdr = const_cast<ETH_HDR*>(reinterpret_cast<const ETH_HDR*>(pckt)); //cast to ethernet header
    u_short ether_type = ntohs(eth_hdr->type);           //switch byteOrder network to host

    IP_HDR *ip_hdr;
    ip_hdr = const_cast<IP_HDR*>(               //cast data to IP header
                reinterpret_cast<const IP_HDR*>
                (&pckt[eth_hdr_len]));
    int ip_hdr_len = ip_hdr->hdr_len * 4;

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
        printf("%d\n", ntohs(ip_hdr->total_len));

        printf("SRC_PORT: %d\nDST_PORT: %d\n", ntohs(tcp_hdr->src_port), ntohs(tcp_hdr->dst_port));
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

