#include <pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

void usage() {
  printf("syntax: pcap-test <interface>\n");
  printf("sample: pcap-test wlan0\n");
}

typedef struct {
  char * dev_;
} Param;

Param param = {
  .dev_ = NULL
};

bool parse(Param * param, int argc, char * argv[]) {
  if (argc != 2) {
    usage();
    return false;
  }
  param -> dev_ = argv[1];
  return true;
}

int main(int argc, char * argv[]) {
  if (!parse( & param, argc, argv))
    return -1;

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t * pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
  if (pcap == NULL) {
    fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr * header;
    const u_char * packet;
    int res = pcap_next_ex(pcap, & header, & packet);
    if (res == 0) continue;
    if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
      printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
      printf("\n-----------------------------------------------------------------------\n");
      break;
    }



    uint8_t * upacket = (uint8_t * ) packet;

    if (upacket[12] == 0x08 && upacket[13] == 0x00) {
      if (upacket[23] == 6) {
		printf("\n%u bytes captured\n", header->caplen);
        printf("\nDestination MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n", upacket[0], upacket[1], upacket[2], upacket[3], upacket[4], upacket[5]);
        printf("Source MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n", upacket[6], upacket[7], upacket[8], upacket[9], upacket[10], upacket[11]);
        printf("\n-----------------------------------------------------------------------\n");
        printf("\nIP Header:\n");
        for (int i = 0; i < 20; i++) {
          printf("%02x ", upacket[14 + i]);
          if (i % 4 == 3) printf("\n");
        }
        printf("Source IP Address : %d.%d.%d.%d\n", upacket[26], upacket[27], upacket[28], upacket[29]);
        printf("Destination IP Address : %d.%d.%d.%d\n", upacket[30], upacket[31], upacket[32], upacket[33]);
        printf("\n-----------------------------------------------------------------------\n");
      }

      printf("\nTCP Source Port : %d\n", (upacket[34] << 8) | upacket[35]);
      printf("TCP Destination Port : %d\n", (upacket[36] << 8) | upacket[37]);
      printf("\n-----------------------------------------------------------------------\n");

      printf("10 Bytes Payload: \n");
      for (int i = 0; i < 10; i++) {
        printf("%02x ", upacket[54 + i]);
        if (i % 10 == 9) printf("\n");
      }

    }
  }
  pcap_close(pcap);

  return 0;
}
