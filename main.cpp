#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#define eth_hdr_len 14
#define ip_hdr_len 40

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

};

void print_packet_info(const u_char *pckt);
void print_MAC(const u_char *data);
void print_IP(const u_char *data);

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
//  if (argc != 2) {  // Check argument.
//    usage();
//    return -1;
//  }

    char* dev = "ens33";
  /*char* dev = argv[1];*/         // device name
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
    print_packet_info(packet);                     //print packet information
  }

  pcap_close(handle);
  return 0;
}

void print_packet_info(const u_char *pckt){
    ETH_HDR *eth_hdr;
    eth_hdr = const_cast<ETH_HDR*>(reinterpret_cast<const ETH_HDR*>(pckt));
    u_short ether_type = ntohs(eth_hdr->type);           //switch byteOrder network to host

    if (ether_type == 0x0800) {               //if ethernet type is IP
        //print destination MAC address
        printf("==============================================\n");
        printf("DST_MAC: ");
        print_MAC(eth_hdr->dst_MAC);

        //print source MAC address
        printf("SRC_MAC: ");
        print_MAC(eth_hdr->src_MAC);

        IP_HDR *ip_hdr;
        ip_hdr = const_cast<IP_HDR*>(reinterpret_cast<const IP_HDR*>(&pckt[eth_hdr_len]));
        printf("SRC_IP: ");
        print_IP(ip_hdr->src_ip_addr);
        printf("DST_IP: ");
        print_IP(ip_hdr->dst_ip_addr);
        printf("IP_ver: ");
        printf("%d\n", ip_hdr->version);

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

