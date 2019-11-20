#include <iostream>
#include <iterator>
#include <map>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <climits>
#include <time.h>
#include <arpa/inet.h>
#include <list>

using namespace std;

//Global variables
int numPackets = 0;
int totalPacketSize = 0;
int currentMin = INT_MAX;
int currentMax = INT_MIN;
struct timeval startTime;
struct timeval endTime;
map<char *, int> sourceEth;
map<char *, int> destEth;
map<char *, int> sourceIP;
map<char *, int> destIP;
list<u_short> destPorts;
list<u_short> sourcePorts;

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char* argv[]) {
    // Initialize the package capture
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

    double usec = endTime.tv_usec - startTime.tv_usec;
    double timeLast = endTime.tv_sec - startTime.tv_sec + usec / 1000000;

    // print out info part
    cout << "The packet starts at " << ctime((const time_t*)&startTime.tv_sec);
    cout << "The packet lasts " << timeLast << " seconds" << endl;
    cout << "There are " << numPackets << " packets in total" << endl;
    cout << "Average packet size is " << totalPacketSize / numPackets << " Bytes" << endl;
    cout << "The biggest packet is " << currentMax << " Bytes" << endl;
    cout << "The smallest packet is " << currentMin << " Bytes" << endl;

    auto it = sourceEth.begin();
    while (it != sourceEth.end()) {
        char* ethStr = it->first;
        int amount = it->second;
        cout << "Ethernet address " << ethStr << " has " << amount << " packets related as source" << endl;
        it++;
    }

    it = destEth.begin();
    while (it != destEth.end()) {
        char* destStr = it->first;
        int amount = it->second;
        cout << "Ethernet address " << destStr << " has " << amount << " packets related as destination" << endl;
        it++;
    }

    it = sourceIP.begin();
    while (it != sourceIP.end()) {
        char* IPStr = it -> first;
        int amount = it -> second;
        cout << "IP address " << IPStr << " has " << amount << " packets related as source" << endl;
        it ++;
    }

    it = destIP.begin();
    while (it != destIP.end()) {
        char* IPStr = it -> first;
        int amount = it -> second;
        cout << "IP address " << IPStr << " has " << amount << " packets related as destination" << endl;
        it ++;
    }

    destPorts.sort();
    sourcePorts.sort();
    destPorts.unique();
    sourcePorts.unique();

    cout << "These ports are used in communication as source: ";
    list<u_short>::const_iterator iterator;
    for (iterator = sourcePorts.begin(); iterator != sourcePorts.end(); ++iterator) {
        std::cout << to_string(*iterator) << " ";
    }
    cout << '\n';

    cout << "These ports are used in communication as destination: ";
    for (iterator = destPorts.begin(); iterator != destPorts.end(); ++ iterator) {
        cout << to_string(*iterator) << " ";
        it ++;
    }
    cout << '\n';

    return 0;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ether_header *ethernetHeader;
    struct ip *ipHeader;
    struct udphdr *udpHeader;

    // Put time within here if it is the first one
    if (numPackets == 0) {
        startTime = pkthdr->ts;
    } else {
        endTime = pkthdr->ts;
    }

    //ethernet address
    ethernetHeader = (struct ether_header*)packet;

    char* sourceEthStr = ether_ntoa(
            reinterpret_cast<const ether_addr *>(&ethernetHeader->ether_shost));
    cout << sourceEthStr << endl;
    if (sourceEth.find(sourceEthStr) == sourceEth.end()) {
        sourceEth.insert(pair<char *, int>(sourceEthStr, 1));
    } else {
        int currentNum = sourceEth.at(sourceEthStr);
        sourceEth.erase(sourceEthStr);
        sourceEth.insert(pair<char*, int>(sourceEthStr, currentNum + 1));
    }

    char* destEthStr = ether_ntoa(
            reinterpret_cast<const ether_addr *>(&ethernetHeader->ether_shost));
    cout << destEthStr << endl;
    if (destEth.find(destEthStr) == destEth.end()) {
        destEth.insert(pair<char *, int> (destEthStr, 1));
    } else {
        int currentNum = destEth.at(destEthStr);
        destEth.erase(destEthStr);
        destEth.insert(pair<char *, int>(destEthStr, currentNum + 1));
    }

    // IP address
    ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    char* destIPStr = inet_ntoa(ipHeader->ip_dst);
    char* sourceIPStr = inet_ntoa(ipHeader->ip_src);
    cout << sourceIPStr << endl;
    cout << destIPStr << endl;
    cout << endl;
    if (sourceIP.find(sourceIPStr) == sourceIP.end()) {
        sourceIP.insert(pair<char *, int>(sourceIPStr, 1));
    } else {
        int currentNum = sourceIP.at(sourceIPStr);
        sourceIP.erase(sourceIPStr);
        sourceIP.insert(pair<char*, int>(sourceIPStr, currentNum + 1));
    }
    if (destIP.find(destIPStr) == destIP.end()) {
        destIP.insert(pair<char *, int>(destIPStr, 1));
    } else {
        int currentNum = destIP.at(destIPStr);
        destIP.erase(destIPStr);
        destIP.insert(pair<char*, int>(destIPStr, currentNum + 1));
    }

    udpHeader = (udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    sourcePorts.push_front(udpHeader->uh_sport);
    destPorts.push_front(udpHeader->uh_dport);


    // Size management
    numPackets++;
    int size = pkthdr->len;
    if (size > currentMax) currentMax = size;
    if (size < currentMin) currentMin = size;
    totalPacketSize += size;

    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        //TODO: do something for IP
    } else  if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_ARP) {
        //TODO: do something for ARP
    } else {
        cout << "Not a type supported, aborting" << endl;
        return;
    }
}