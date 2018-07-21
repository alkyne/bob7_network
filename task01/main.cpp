#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include </usr/include/net/ethernet.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
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
		//printf("%u bytes captured\n", header->caplen);


		struct  ether_header *eh;
		eh = (struct ether_header *)packet;
		short ether_type = eh->ether_type;

//	if(ntohs(eh->ether_type)==0x0800) {

		// check if ether type is 0x0800
		if(packet[12] == 0x08 && packet[13]==0x00) {

			// source mac
			printf("<Destination MAC>\n");
			for (int i=0; i<6; i++)
				printf("%x ", packet[i]);

			printf("\n");
			printf("<Source MAC>\n");
			for (int i=6; i<12; i++)
				printf("%x ", packet[i]);

			printf("\n");


		// IP header start
		const u_char* ip_header = packet + 14;


		// source IP
		printf("<Source IP>\n");
		for(int i=12; i<=15; i++) {
			printf("%d ", ip_header[i]);
		}
		printf("\n");
	
		// destination IP
		printf("<Destination IP>\n");
		for(int i=16; i<=19; i++) {
			printf("%d ", ip_header[i]);
		}
		printf("\n");

		// slice back 4 bit
		short ip_header_len = (ip_header[0] & 0xF) * 4;
		const u_char* tcp_header = ip_header + ip_header_len;
		printf("%d\n", ip_header_len);

		printf("<Source port>\n");
		printf("%d\n", tcp_header[0]*256 + tcp_header[1]);

		printf("<Destination port>\n");
		printf("%d\n", tcp_header[2]*256 + tcp_header[3]);

	} // end if

	printf("\n");
  } // end while

  pcap_close(handle);
  return 0;
}
