#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <my_pckt.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {             // Check argument.
    usage();
    return -1;
  }

  char* dev = argv[1];         // device name
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
    printf("==============================================\n");
    printf("%u bytes captured\n", header->caplen);
    print_packet_info(packet, header->caplen);                     //print packet information
    printf("==============================================\n");
  }

  pcap_close(handle);
  return 0;
}
