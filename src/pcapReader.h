#ifndef PCAPREADER_H_
#define PCAPREADER_H_

#include <pcap.h>
#include <inttypes.h>

// 定义pcap_packet结构体
struct pcap_packet {
    uint64_t timestamp; // nano second timestamp
    int length;         // packet length
    uint8_t *data;
};

struct pcap_reader {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_packet *packets;
    int packet_count;
};

// Constructor
struct pcap_reader* initPcapReader(char* pcap_name);
// Destructor
void freePcapReader(struct pcap_reader* reader);
// Read the next packet
int next_packet(struct pcap_reader* reader);
// Get last packet
// struct pcap_packet* last_packet(struct pcap_reader* reader)
//     { return reader->packets + (reader->packet_count - 1);  }


#endif