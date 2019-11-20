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
#include <forward_list>

using namespace std;

//Global variables
int numPackets = 0;
int totalPacketSize = 0;
int currentMin = INT_MAX;
int currentMax = INT_MIN;
struct timeval startTime;
struct timeval endTime;
map<string, int> sourceEths;
map<string, int> destEths;
map<string, int> sourceIPs;
map<string, int> destIPs;
forward_list<u_short> destPorts;
forward_list<u_short> sourcePorts;
forward_list<string> ARPEth;
forward_list<string> ARPIP;

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

    for (auto it = sourceEths.begin(); it != sourceEths.end(); ++it) {
        string ethStr = it->first;
        int amount = it->second;
        cout << "Ethernet address " << ethStr << " has " << amount << " packets related as source" << endl;
    }

    for (auto it = destEths.begin(); it != destEths.end(); ++it) {
        string destStr = it->first;
        int amount = it->second;
        cout << "Ethernet address " << destStr << " has " << amount << " packets related as destination" << endl;
    }

    for (auto it = sourceIPs.begin(); it != sourceIPs.end(); ++it) {
        string IPStr = it -> first;
        int amount = it -> second;
        cout << "IP address " << IPStr << " has " << amount << " packets related as source" << endl;
        it ++;
    }

    for (auto it = sourceIPs.begin(); it != sourceIPs.end(); ++it) {
        string IPStr = it -> first;
        int amount = it -> second;
        cout << "IP address " << IPStr << " has " << amount << " packets related as destination" << endl;
        it ++;
    }

    destPorts.sort();
    sourcePorts.sort();
    destPorts.unique();
    sourcePorts.unique();

    cout << "These ports are used in communication as source: ";
    for (forward_list<u_short>::const_iterator iterator = sourcePorts.begin(); iterator != sourcePorts.end(); ++iterator) {
        std::cout << to_string(*iterator) << " ";
    }
    cout << '\n';

    cout << "These ports are used in communication as destination: ";
    for (forward_list<u_short>::const_iterator iterator = destPorts.begin(); iterator != destPorts.end(); ++ iterator) {
        cout << to_string(*iterator) << " ";
    }
    cout << '\n';

    ARPIP.sort();
    ARPEth.sort();
    ARPIP.unique();
    ARPEth.unique();
    cout << "These ethernet address involve ARP: " << endl;
    for(forward_list<string>::const_iterator iterator = ARPEth.begin(); iterator != ARPEth.end(); ++iterator) {
        cout <<*iterator << endl;
    }

    cout << "These IP address involve ARP: " << endl;
    for(forward_list<string>::const_iterator iterator = ARPIP.begin(); iterator != ARPIP.end(); ++iterator) {
        cout << *iterator << endl;
    }

    return 0;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ether_header *ethernetHeader;
    struct ip *ipHeader;
    struct udphdr *udpHeader;
    ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    char destIP[INET_ADDRSTRLEN] = "";
    char sourceIP[INET_ADDRSTRLEN]= "";
    inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, sizeof(destIP));
    string sourceIPStr(sourceIP);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, sizeof(sourceIP));
    string destIPStr(destIP);
    ethernetHeader = (struct ether_header*)packet;
    char* destEth = ether_ntoa(
            reinterpret_cast<const ether_addr *>(&ethernetHeader->ether_dhost));
    string destEthStr (destEth);
    char* sourceEth = ether_ntoa(
            reinterpret_cast<const ether_addr *>(&ethernetHeader->ether_shost));
    string sourceEthStr(sourceEth);

    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        //TODO: do something for IP
    } else  if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_ARP) {
        ARPEth.push_front(sourceEthStr);
        ARPEth.push_front(destEthStr);
        ARPIP.push_front(sourceIPStr);
        ARPIP.push_front(destIPStr);
    } else {
        cout << "Not a type supported, aborting" << endl;
        return;
    }

    // Put time within here if it is the first one
    if (numPackets == 0) {
        startTime = pkthdr->ts;
    } else {
        endTime = pkthdr->ts;
    }

    //ethernet address

    if (sourceEths.count(sourceEthStr) == 0) {
        sourceEths.insert(sourceEths.begin(),pair<string, int>(sourceEthStr, 1));
    } else {
        int currentNum = sourceEths.at(sourceEthStr);
        sourceEths.erase(sourceEthStr);
        sourceEths.insert(sourceEths.begin(),pair<string, int>(sourceEthStr, currentNum + 1));
    }


    if (destEths.count(destEthStr) == 0) {
        destEths.insert(destEths.begin(),pair<string, int> (destEthStr, 1));
    } else {
        int currentNum = destEths.at(destEthStr);
        destEths.erase(destEthStr);
        destEths.insert(destEths.begin(),pair<string, int>(destEthStr, currentNum + 1));
    }

    // IP address

    if (sourceIPs.count(sourceIPStr) == 0) {
        sourceIPs.insert(sourceIPs.begin(),pair<string, int>(sourceIPStr, 1));
    } else {
        int currentNum = sourceIPs.at(sourceIPStr);
        sourceIPs.erase(sourceIPStr);
        sourceIPs.insert(sourceIPs.begin(),pair<string, int>(sourceIPStr, currentNum + 1));
    }
    if (destIPs.count(destIPStr) == 0) {
        destIPs.insert(destIPs.begin(),pair<string, int>(destIPStr, 1));
    } else {
        int currentNum = destIPs.at(destIPStr);
        destIPs.erase(destIPStr);
        destIPs.insert(destIPs.begin(),pair<string, int>(destIPStr, currentNum + 1));
    }

    udpHeader = (udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    sourcePorts.push_front(ntohs(udpHeader->uh_sport));
    destPorts.push_front(ntohs(udpHeader->uh_dport));


    // Size management
    numPackets++;
    int size = pkthdr->len;
    if (size > currentMax) currentMax = size;
    if (size < currentMin) currentMin = size;
    totalPacketSize += size;


}