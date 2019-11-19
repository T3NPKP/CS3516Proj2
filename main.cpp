#pragma clang diagnostic push
#pragma ide diagnostic ignored "modernize-use-nullptr"
#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <climits>
#include <time.h>

using namespace std;
int numPackets = 0;
int totalPacketSize = 0;
int currentMin = INT_MAX;
int currentMax = INT_MIN;
struct timeval startTime;
struct timeval endTime;

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char* argv[]) {
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (argc != 2) {
        cout << "Illegal input, must put only the file path" << endl;
        return 1;
    } else {
        descr = pcap_open_offline(argv[1], errbuf);
        cout << "Opening file" << argv[1] << endl;
    }
    if (descr == NULL) {
        cout << "pcap_open() failed: " << errbuf << endl;
        return 1;
    }

    if (pcap_datalink(descr) != DLT_EN10MB) {
        cout << "A package not captured from Ethernet, aborting" << endl;
        return 1;
    }

    cout << "File opened, analyzing..." << endl;

    if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
        cout << "pcap_loop() failed: " << pcap_geterr(descr);
        return 1;
    }

    double timeLast = endTime.tv_sec - startTime.tv_sec + (endTime.tv_usec - startTime.tv_usec)/ 1000000;

    cout << "The packet starts at " << ctime((const time_t*)&startTime.tv_sec) << endl;
    cout << "The packet lasts " << timeLast << " seconds" << endl;
    cout << "There are " << numPackets << " packets in total" << endl;
    cout << "Average packet size is " << totalPacketSize / numPackets << " Bytes" << endl;
    cout << "The biggest packet is " << currentMax << " Bytes" << endl;
    cout << "The smallest packet is " << currentMin << " Bytes" << endl;

    return 0;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const struct ether_header *ethernetHeader;
    const struct ip *ipHeader;
    const struct udphdr *udpHeader;
    struct ether_header *eth_header;
    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];

    // Put time within here if it is the first one
    if (numPackets == 0) {
        startTime = pkthdr->ts;
    } else {
        endTime = pkthdr->ts;
    }

    // Size management
    numPackets++;
    int size = pkthdr->len;
    if (size > currentMax) currentMax = size;
    if (size < currentMin) currentMin = size;
    totalPacketSize += size;
    eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        printf("IP\n");
    } else  if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        printf("ARP\n");
    } else {
        cout << "Not a type supported, aborting" << endl;
        return;
    }
}
#pragma clang diagnostic pop