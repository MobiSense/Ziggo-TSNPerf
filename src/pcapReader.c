#include "pcapReader.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static int max_packets = 100;

// Initialization
struct pcap_reader* initPcapReader(char* pcap_name) {
    struct pcap_reader* reader = (struct pcap_reader*) malloc(sizeof(struct pcap_reader));

    reader->handle = NULL;
    reader->packets = NULL;
    reader->packet_count = 0;

    // 按照纳秒精度打开PCAP文件
    // https://stackoverflow.com/questions/17636334/read-nanosecond-pcap-file-using-libpcap
    reader->handle = pcap_open_offline_with_tstamp_precision(pcap_name, PCAP_TSTAMP_PRECISION_NANO, reader->errbuf);
    if (reader->handle == NULL) {
        fprintf(stderr, "Couldn't open pcap file: %s\n", reader->errbuf);
        exit(2);
    }

    // 分配内存给数据包数组
    reader->packets = (struct pcap_packet *)malloc(sizeof(struct pcap_packet) * max_packets);
    if (reader->packets == NULL) {
        fprintf(stderr, "Not enough memory\n");
        exit(1);
    }

    return reader;
}

void freePcapReader(struct pcap_reader* reader) {
    if (reader) {
        for (int i = 0; i < reader->packet_count; i++) {
            free(reader->packets[i].data);
        }
        free(reader->packets);
        free(reader);
    }
}

int next_packet(struct pcap_reader* reader) {
    const u_char *packet_data;
    struct pcap_pkthdr header;
    if ((packet_data = pcap_next(reader->handle, &header)) != NULL) {
        if (reader->packet_count >= max_packets) {
            // 扩展数组大小，如果需要
            max_packets *= 2;
            reader->packets = (struct pcap_packet *)realloc(reader->packets, sizeof(struct pcap_packet) * max_packets);
            if (reader->packets == NULL) {
                fprintf(stderr, "Not enough memory\n");
                return 1;
            }
        }

        // FIXME: need nanosecond level precision
        reader->packets[reader->packet_count].timestamp = (uint64_t)header.ts.tv_sec * 1000000000 + header.ts.tv_usec; // libpcap expects tv_usec to be nanos if using nanosecond precision.
        reader->packets[reader->packet_count].length = header.len;
        reader->packets[reader->packet_count].data = (uint8_t *)malloc(header.len);
        if (reader->packets[reader->packet_count].data == NULL) {
            fprintf(stderr, "Not enough memory\n");
            return 1;
        }
        memcpy(reader->packets[reader->packet_count].data, packet_data, header.len);

        reader->packet_count++;
        return 1;
    }

    return 0;
}
