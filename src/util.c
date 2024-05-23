#include <time.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#include "util.h"

uint64_t get_time_nanosec(clockid_t clkid) {
	struct timespec now;

	clock_gettime(clkid, &now);
	return now.tv_sec * NSEC_PER_SEC + now.tv_nsec;
}

uint64_t get_time_sec(clockid_t clkid) {
	struct timespec now;

	clock_gettime(clkid, &now);
	return now.tv_sec * NSEC_PER_SEC;
}

void copy_file(char *src_file, char *dst_file, bool clear_src) {
	int ch;
	FILE *src, *dst;

	if (src_file == NULL || dst_file == NULL) {
		fprintf(stderr, "ERROR: copy_file: src_file and/or dst_file is not given. This will impact phc2sys and ptp4l stat.\n");
		return;
	}

	/* Open source file for reading */
	src = fopen(src_file, "r");
	if (src == NULL)
		return;

	/* Open destination file for writing in append mode */
	dst = fopen(dst_file, "w");
	if (dst == NULL) {
		fclose(src);
		return;
	}

	/* Copy content from source file to destination file */
	while ((ch = fgetc(src)) != EOF)
		fputc(ch, dst);

	fclose(src);
	fclose(dst);

	/* Clear source file */
	if (clear_src)
		fclose(fopen(src_file, "w"));

	return;
}

void ts_log_start() {
	copy_file("/var/log/ptp4l.log", "/var/log/total_ptp4l.log", 1);
	copy_file("/var/log/phc2sys.log", "/var/log/total_phc2sys.log", 1);
}

void ts_log_stop() {
	copy_file("/var/log/ptp4l.log", "/var/log/captured_ptp4l.log", 0);
	copy_file("/var/log/phc2sys.log", "/var/log/captured_phc2sys.log", 0);
}

#define VLAN_ID 3
// #define VLAN_ID 1

/* Pre-fill TSN packet with default and user-defined parameters */
void setup_tsn_vlan_packet(struct user_opt *opt, tsn_packet *pkt) {
	memset(pkt, 0xab, opt->packet_size);

	memcpy(&pkt->src_mac, opt->src_mac_addr, sizeof(pkt->src_mac));
	memcpy(&pkt->dst_mac, opt->dst_mac_addr, sizeof(pkt->dst_mac));

	pkt->vlan_hdr = htons(ETHERTYPE_VLAN);
	pkt->vlan_id = VLAN_ID;
	pkt->vlan_prio = opt->vlan_prio;

	// pkt->eth_hdr = htons(ETH_P_TSN);

	/* WORKAROUND: transmit only 0xb62c ETH UADP header packets
	 *  due to a bug where IEEE 1722 (ETH_P_TSN) packets are
	 *  always steered into RX Q0 regardless of its VLAN
	 *  priority
	 */
	// pkt->eth_hdr = htons(0xb62c);
	pkt->eth_hdr = htons(opt->eth_hdr);
}