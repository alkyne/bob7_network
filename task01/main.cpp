#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include </usr/include/net/ethernet.h>

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}


void Print_ip(const u_char * ip) {

	for(int i=0; i<3; i++)
		printf("%d.", *(ip+i));
	printf("%d\n", *(ip+3));

}

void Print_mac(const u_char * mac) {

	for(int i=0; i<5; i++)
		printf("%x:",*(mac+i));
	printf("%x\n", *(mac+5));
}

void Print_data(const u_char * data) {

	for(int i=0; i<15; i++)
		printf("%c", data[i]);
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


		// check if ether type is 0x0800
		if(packet[12] == 0x08 && packet[13]==0x00) {

			// Destination mac
			printf("<Destination MAC>\n");
			Print_mac(&packet[0]);

			// Source mac
			printf("<Source MAC>\n");
			Print_mac(&packet[6]);

			// IP header start
			const u_char* ip_header = packet + 14;

			// source IP
			printf("<Source IP>\n");
			Print_ip(&ip_header[12]);

			// Destination IP
			printf("<Destination IP>\n");
			Print_ip(&ip_header[16]);

			// slice back 4 bit
			short ip_header_len = (ip_header[0] & 0xF) * 4;
			const u_char* tcp_header = ip_header + ip_header_len;
			// printf("ip header len : %d\n", ip_header_len);

			printf("<Source port>\n");
			printf("%d\n", tcp_header[0]*256 + tcp_header[1]);

			printf("<Destination port>\n");
			printf("%d\n", tcp_header[2]*256 + tcp_header[3]);

			short tcp_header_len = ((tcp_header[12] & 0xF0 ) * 4) >> 4;
			//printf("tcp header len : %d\n", tcp_header_len);

			const u_char * data = tcp_header + tcp_header_len;
			printf("<Data 16 byte>\n");
			Print_data(data);
			

		} // end if

		printf("\n");
	} // end while

	pcap_close(handle);
	return 0;
}
