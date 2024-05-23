#ifndef UTIL_H_
#define UTIL_H_

#include <time.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#define NSEC_PER_SEC 1000000000L
#define exit_with_error(s) {fprintf(stderr, "Error: %s\n", s); exit(EXIT_FAILURE);}

struct user_opt {
    uint8_t mode;		//App mode: TX/RX
	uint8_t tx_mode;

    int verbose;
	int ziggo_analysis; // use ziggo to analyze rx & tx timestamp

    char *pcapfilename;
	char *configfilename;
    char *ifname;

    unsigned char dst_mac_addr[6];
    unsigned char src_mac_addr[6];
    uint32_t ifindex;
	uint16_t eth_hdr;

    /* TX control */
	uint32_t socket_prio;
	uint8_t vlan_prio;
	// uint32_t interval_ns;		//Cycle time or time between packets
	uint32_t offset_ns;		//TXTIME transmission target offset from 0th second
	uint32_t early_offset_ns;	//TXTIME early offset before transmission

    uint8_t enable_txtime;
    clockid_t clkid;

	uint64_t basetime;

    /* For debug */
    uint32_t packet_size;
	uint32_t frames_to_send;
	uint32_t interval_ns;		//Cycle time or time between packets
    int enable_hwts;
};

struct custom_payload {
	uint32_t tx_queue;
	uint32_t seq;
	uint64_t tx_timestampA;
	uint64_t rx_timestampD;
};

/* Struct for VLAN packets with 1722 header */
typedef struct __attribute__ ((packed)) {
	/* Ethernet */
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	/* VLAN */
	uint16_t vlan_hdr;
	uint8_t vlan_prio;
	uint8_t vlan_id;
	/* Header */
	uint16_t eth_hdr;
	/* Payload */
	void *payload;
} tsn_packet;

uint64_t get_time_nanosec(clockid_t clkid);
uint64_t get_time_sec(clockid_t clkid);
void copy_file(char *src_file, char *dst_file, bool clear_src);
void ts_log_start();
void ts_log_stop();

void setup_tsn_vlan_packet(struct user_opt *opt, tsn_packet *pkt);

#endif
