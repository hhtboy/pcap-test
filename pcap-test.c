#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "my_header.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_packet_info(u_char* packet, struct pcap_pkthdr* header)
{
	// mac addr
	struct ethheader* pEth = (struct ethheader*)(packet);
	unsigned int eth_size = sizeof(struct ethheader);

	// ip addr
	struct ipheader* pIp = (struct ipheader*)(packet + eth_size);
	//print packet data only if packet is TCP
	if(pIp->iph_protocol == 0x6) {
		// print mac addr
		printf("src mac : ");
		for(int i = 0 ; i < 5 ; i ++) {
			printf("%02x:", pEth->ether_shost[i]);
		}
		printf("%x\n", pEth->ether_shost[5]);

		printf("dst mac : ");
		for(int i = 0 ; i < 5 ; i ++) {
			printf("%02x:", pEth->ether_dhost[i]);
		}
		printf("%x\n", pEth->ether_dhost[5]);

		//print ip addr
		printf("src ip : ");
		unsigned int ip = pIp->iph_sourceip.s_addr;
		printf("%d.%d.%d.%d\n", ip % 256, (ip >> 8) % 256, (ip>>16) %256, ip>>24);
		unsigned int ip_size = pIp->iph_ihl * 4; 

		printf("dst ip : ");
		ip = pIp->iph_destip.s_addr;
		printf("%d.%d.%d.%d\n", ip % 256, (ip >> 8) % 256, (ip>>16) %256, ip>>24);

		//print tcp port
		struct tcpheader *tcp = (struct tcpheader *)(packet + eth_size + ip_size);
		printf("src port : %u\n", ntohs(tcp->tcp_sport));
		printf("dst port : %u\n", ntohs(tcp->tcp_dport));
		unsigned int tcp_size = (tcp->tcp_offx2 & 0xf0) >> 4;

		//print payload
		unsigned int total_header_size = eth_size + ip_size + tcp_size * 4;
		unsigned int payload_size = header->caplen - total_header_size;
		const unsigned char* payload = (unsigned char*)(packet + total_header_size);
		unsigned int print_size = payload_size < 20 ? payload_size : 20;
		for(int i = 0 ; i < print_size ; i++) {
			printf("%c", *(payload + i));
		}
		printf("\n");

	}
	else return;
			

	


}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
		print_packet_info(packet, header);
	}

	pcap_close(pcap);
}
