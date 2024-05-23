#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/errqueue.h>
#include <linux/if_ether.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <linux/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "pcapSender.h"

/* Retrieve the hardware timestamp stored in CMSG */
static uint64_t get_timestamp(struct msghdr *msg, int verbose) {
	struct timespec *ts = NULL;
	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level != SOL_SOCKET)
			continue;

		switch (cmsg->cmsg_type) {
		case SO_TIMESTAMPNS:
		case SO_TIMESTAMPING:
			ts = (struct timespec *) CMSG_DATA(cmsg);
			break;
		default: /* Ignore other cmsg options */
			break;
		}
	}

	if (!ts) {
		if (verbose)
			fprintf(stderr, "Error: timestamp null. Is ptp4l initialized?\n");
		return 0;
	}

	return (ts[2].tv_sec * NSEC_PER_SEC + ts[2].tv_nsec);
}

static uint64_t extract_ts_from_cmsg(int sock, int recvmsg_flags, int verbose) {
	char data[256];
	struct msghdr msg;
	struct iovec entry;
	struct sockaddr_in from_addr;
	int ret = 0;
	struct {
		struct cmsghdr cm;
		char control[512];
	} control;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &entry;
	msg.msg_iovlen = 1;
	entry.iov_base = data;
	entry.iov_len = sizeof(data);
	msg.msg_name = (caddr_t)&from_addr;
	msg.msg_namelen = sizeof(from_addr);
	msg.msg_control = &control;
	msg.msg_controllen = sizeof(control);

	ret = recvmsg(sock, &msg, recvmsg_flags|MSG_DONTWAIT);
	if (ret <= 0)
		return 0;

	return get_timestamp(&msg, verbose);
}

int init_tx_socket(struct user_opt *opt, int *sockfd, struct sockaddr_ll *sk_addr) {
	struct ifreq hwtstamp = { 0 };
	struct hwtstamp_config hwconfig = { 0 };
	int sock;

	/* Set up socket */
	sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_8021Q));
	if (sock < 0)
		exit_with_error("socket creation failed");

	sk_addr->sll_ifindex = opt->ifindex;
	memcpy(&sk_addr->sll_addr, opt->dst_mac_addr, ETH_ALEN);

	if (setsockopt(sock, SOL_SOCKET, SO_PRIORITY, &opt->socket_prio,
		       sizeof(opt->socket_prio)) < 0)
		exit_with_error("setsockopt() failed to set priority");

	/* Similar to: hwstamp_ctl -r 1 -t 1 -i <iface>
	 * This enables tx hw timestamping for all packets.
	 */
	int timestamping_flags = SOF_TIMESTAMPING_TX_HARDWARE |
				 SOF_TIMESTAMPING_RAW_HARDWARE;

	strncpy(hwtstamp.ifr_name, opt->ifname, sizeof(hwtstamp.ifr_name)-1);
	hwtstamp.ifr_data = (void *)&hwconfig;
	hwconfig.tx_type = HWTSTAMP_TX_ON;
	hwconfig.rx_filter = HWTSTAMP_FILTER_ALL;

	if (ioctl(sock, SIOCSHWTSTAMP, &hwtstamp) < 0) {
		fprintf(stderr, "%s: %s\n", "ioctl", strerror(errno));
		exit(1);
	}

	if (setsockopt(sock, SOL_SOCKET, SO_TIMESTAMPING, &timestamping_flags,
			sizeof(timestamping_flags)) < 0)
		exit_with_error("setsockopt SO_TIMESTAMPING");

	/* Set socket to use SO_TXTIME to pass the transmit time per packet */
	static struct sock_txtime sk_txtime;
	int use_deadline_mode = 0;
	int receive_errors = 0;

	sk_txtime.clockid = CLOCK_TAI;
	sk_txtime.flags = (use_deadline_mode | receive_errors);
	if (opt->enable_txtime && setsockopt(sock, SOL_SOCKET, SO_TXTIME,
					&sk_txtime, sizeof(sk_txtime))) {
		exit_with_error("setsockopt SO_TXTIME");
	}

	*sockfd = sock;
	return sock;
}

void tx_thread(struct pcap_reader* reader,
               struct user_opt *opt,
               int *sockfd,
               struct sockaddr_ll *sk_addr) {
	struct timeval timeout;
	fd_set readfs, errorfs;
	uint64_t tx_timestamp;
	uint64_t tx_timestampA;
	uint64_t tx_timestampB;
	uint64_t looping_ts;
	struct timespec ts;
	int res;
	int ret;
    int verbose = opt->verbose;

	clockid_t clkid = opt->clkid;
	int sock = *sockfd;
	uint64_t basetime = (opt->basetime == 0) ? get_time_sec(clkid) + (NSEC_PER_SEC * 2) :
											 ((get_time_nanosec(clkid) - opt->basetime) / (uint64_t)opt->interval_ns + (uint64_t)10) * (uint64_t)opt->interval_ns + opt->basetime - (uint64_t)opt->offset_ns;
    uint64_t ts_num;
	uint32_t seq = 1;

	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	char control[CMSG_SPACE(sizeof(uint64_t))] = {};

	/* Construct the packet msghdr, CMSG and initialize packet payload */
	// iov.iov_base = &tsn_pkt->vlan_prio;
	// iov.iov_len = (size_t) opt->packet_size - 14;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = sk_addr;
	msg.msg_namelen = sizeof(struct sockaddr_ll);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_TXTIME;
	cmsg->cmsg_len = CMSG_LEN(sizeof(uint64_t));

    for (int i = 0; i < reader->packet_count; i++) {
		if (i > 0 && reader->packets[i].timestamp <= reader->packets[i - 1].timestamp)
			continue;
        ts_num = basetime + opt->offset_ns - opt->early_offset_ns + 
                 (reader->packets[i].timestamp - reader->packets[0].timestamp);
        ts.tv_sec = ts_num / NSEC_PER_SEC;
        ts.tv_nsec = ts_num % NSEC_PER_SEC;

		ret = clock_nanosleep(clkid, TIMER_ABSTIME, &ts, NULL);
		if (ret) {
			fprintf(stderr, "Error: failed to sleep %d: %s", ret, strerror(ret));
			break;
		}

		tx_timestampA = get_time_nanosec(CLOCK_REALTIME);
		// memcpy(&payload->seq, &seq, sizeof(uint32_t));
		// memcpy(&payload->tx_timestampA, &tx_timestampA, sizeof(uint64_t));
		iov.iov_base = reader->packets[i].data + 14;
        iov.iov_len = (size_t) reader->packets[i].length - 14;

		/* Update CMSG tx_timestamp and payload before sending */
		// tx_timestamp = looping_ts + opt->early_offset_ns;
        tx_timestamp = ts_num + opt->early_offset_ns;
		*((__u64 *) CMSG_DATA(cmsg)) = tx_timestamp;

		ret = sendmsg(sock, &msg, 0);
		if (ret < 1)
			printf("sendmsg failed: %m");

		seq++;

		// if (opt->enable_hwts) 
        if (0) {
			//Note: timeout is duration not timestamp
			timeout.tv_usec = 2000;
			FD_ZERO(&readfs);
			FD_ZERO(&errorfs);
			FD_SET(sock, &readfs);
			FD_SET(sock, &errorfs);

			res = select(sock + 1, &readfs, 0, &errorfs, &timeout);
		} else {
			res = 0;
		}

		if (res > 0) {
			if (FD_ISSET(sock, &errorfs) && verbose)
				fprintf(stderr, "CSMG txtimestamp has error\n");

			tx_timestampB = extract_ts_from_cmsg(sock, MSG_ERRQUEUE, verbose);

			/* Result format: seq, user txtime, hw txtime */
			if (verbose)
				fprintf(stdout, "%u\t%lu\t%lu\n",
					seq - 1,
					tx_timestampA,
					tx_timestampB);
		} else {
			/* Print 0 if txtimestamp failed to return in time,
			 * either indicating hwtstamp is not enabled OR
			 * packet failed to transmit.
			 */
			if (verbose) {
				// fprintf(stdout, "%u %lu 0\n", seq - 1, tx_timestampA);
				fprintf(stdout, "%u %lu 0\n", seq - 1, tx_timestamp);
			}
		}
		fflush(stdout);
	}

	// close(sock);
	return;
}

void tx_periodically_thread(struct pcap_reader* reader,
							struct user_opt *opt,
							int *sockfd,
							struct sockaddr_ll *sk_addr) {
	struct timeval timeout;
	fd_set readfs, errorfs;
	uint64_t tx_timestamp;
	uint64_t tx_timestampA;
	uint64_t tx_timestampB;
	uint64_t looping_ts;
	struct timespec ts;
	int res;
	int ret;
    int verbose = opt->verbose;

	int count = opt->frames_to_send < reader->packet_count ?
				opt->frames_to_send : reader->packet_count;

	clockid_t clkid = opt->clkid;
	int sock = *sockfd;
    uint64_t basetime = (opt->basetime == 0) ? get_time_sec(clkid) + (NSEC_PER_SEC * 2) :
											 ((get_time_nanosec(clkid) - opt->basetime) / (uint64_t)opt->interval_ns + (uint64_t)10) * (uint64_t)opt->interval_ns + opt->basetime - (uint64_t)opt->offset_ns;
    uint64_t ts_num;
	uint32_t seq = 1;

	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	char control[CMSG_SPACE(sizeof(uint64_t))] = {};

	/* Construct the CMSG */
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = sk_addr;
	msg.msg_namelen = sizeof(struct sockaddr_ll);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_TXTIME;
	cmsg->cmsg_len = CMSG_LEN(sizeof(uint64_t));

    for (int i = 0; i < count; i++) {
	// for (int i = 0; i < 1000; i++) {
        ts_num = basetime + (uint64_t)opt->offset_ns - (uint64_t)opt->early_offset_ns + (uint64_t)opt->interval_ns * (uint64_t)i;
                //  (reader->packets[i].timestamp - reader->packets[0].timestamp);
        ts.tv_sec = ts_num / NSEC_PER_SEC;
        ts.tv_nsec = ts_num % NSEC_PER_SEC;

		ret = clock_nanosleep(clkid, TIMER_ABSTIME, &ts, NULL);
		if (ret) {
			fprintf(stderr, "Error: failed to sleep %d: %s", ret, strerror(ret));
			break;
		}

		tx_timestampA = get_time_nanosec(CLOCK_REALTIME);
		// memcpy(&payload->seq, &seq, sizeof(uint32_t));
		// memcpy(&payload->tx_timestampA, &tx_timestampA, sizeof(uint64_t));
		iov.iov_base = reader->packets[i].data + 14;
        iov.iov_len = (size_t) reader->packets[i].length - 14;

		/* Update CMSG tx_timestamp and payload before sending */
		// tx_timestamp = looping_ts + opt->early_offset_ns;
        tx_timestamp = ts_num + opt->early_offset_ns;
		*((__u64 *) CMSG_DATA(cmsg)) = tx_timestamp;

		// memcpy(reader->packets[i].data + 20, &tx_timestamp, sizeof(uint64_t));
		memcpy(reader->packets[i].data + (opt->ziggo_analysis ? 20 : 26), &tx_timestamp, sizeof(uint64_t));

		ret = sendmsg(sock, &msg, 0);
		if (ret < 1)
			printf("sendmsg failed: %m");

		seq++;

		// if (opt->enable_hwts) 
        if (0) {
			//Note: timeout is duration not timestamp
			timeout.tv_usec = 2000;
			FD_ZERO(&readfs);
			FD_ZERO(&errorfs);
			FD_SET(sock, &readfs);
			FD_SET(sock, &errorfs);

			res = select(sock + 1, &readfs, 0, &errorfs, &timeout);
		} else {
			res = 0;
		}

		if (res > 0) {
			if (FD_ISSET(sock, &errorfs) && verbose)
				fprintf(stderr, "CSMG txtimestamp has error\n");

			tx_timestampB = extract_ts_from_cmsg(sock, MSG_ERRQUEUE, verbose);

			/* Result format: seq, user txtime, hw txtime */
			if (verbose)
				fprintf(stdout, "%u\t%lu\t%lu\n",
					seq - 1,
					tx_timestampA,
					tx_timestampB);
		} else {
			/* Print 0 if txtimestamp failed to return in time,
			 * either indicating hwtstamp is not enabled OR
			 * packet failed to transmit.
			 */
			if (verbose)
				fprintf(stdout, "%u %lu 0\n", seq - 1, tx_timestamp);
		}
		fflush(stdout);
	}

	// close(sock);
	return;
}


void tx_thread_besteffort(struct user_opt *opt,
						  int *sockfd,
						  struct sockaddr_ll *sk_addr) {
	struct custom_payload *payload;
	struct timeval timeout;
	fd_set readfs, errorfs;
	uint64_t tx_timestampA;
	uint64_t tx_timestampB;
	tsn_packet *tsn_pkt;
	void *payload_ptr;
	uint8_t *offset;
	int res;
	int ret;
	int verbose = opt->verbose;

	// uint64_t looping_ts;
	// struct timespec ts;

	int count = opt->frames_to_send;
	clockid_t clkid = opt->clkid;
	int sock = *sockfd;
	uint32_t seq = 1;

	/* Create packet template */
	tsn_pkt = alloca(opt->packet_size);
	setup_tsn_vlan_packet(opt, tsn_pkt);

	// looping_ts = get_time_sec(CLOCK_REALTIME) + (2 * NSEC_PER_SEC);
	// looping_ts += opt->offset_ns;
	// // looping_ts -= opt->early_offset_ns;
	// ts.tv_sec = looping_ts / NSEC_PER_SEC;
	// ts.tv_nsec = looping_ts % NSEC_PER_SEC;

	payload_ptr = (void *) (&tsn_pkt->payload);
	payload = (struct custom_payload *) payload_ptr;

	offset = (uint8_t *) &tsn_pkt->vlan_prio;

	memcpy(&payload->tx_queue, &opt->socket_prio, sizeof(uint32_t));

	// while (count && !halt_tx_sig) {
	while (count) {
	// while (true) {
		// ret = clock_nanosleep(clkid, TIMER_ABSTIME, &ts, NULL);
		// if (ret) {
		// 	fprintf(stderr, "Error: failed to sleep %d: %s", ret, strerror(ret));
		// 	break;
		// }

		// tx_timestampA = get_time_nanosec(CLOCK_REALTIME);
		memcpy(&payload->seq, &seq, sizeof(uint32_t));
		// memcpy(&payload->tx_timestampA, &tx_timestampA, sizeof(uint64_t));

		ret = sendto(sock,
				offset, /* AF_PACKET generates its own ETH HEADER */
				(size_t) (opt->packet_size) - 14,
				0,
				(struct sockaddr *) sk_addr,
				sizeof(struct sockaddr_ll));
		if (ret < 0)
			exit_with_error("sendto() failed");

		// looping_ts += opt->interval_ns;
		// ts.tv_sec = looping_ts / NSEC_PER_SEC;
		// ts.tv_nsec = looping_ts % NSEC_PER_SEC;
		// interval_ns = INTERVAL_MIN + rand() % (INTERVAL_MAX - INTERVAL_MIN + 1);
		// printf("interval = %d\n", interval_ns);

		count--;
		seq++;

		if (opt->enable_hwts) {
			//Note: timeout is duration not timestamp
			timeout.tv_usec = 2000;
			FD_ZERO(&readfs);
			FD_ZERO(&errorfs);
			FD_SET(sock, &readfs);
			FD_SET(sock, &errorfs);

			res = select(sock + 1, &readfs, 0, &errorfs, &timeout);
		} else {
			res = 0;
		}

		if (res > 0) {
			if (FD_ISSET(sock, &errorfs) && verbose)
				fprintf(stderr, "CSMG txtimestamp has error\n");

			tx_timestampB = extract_ts_from_cmsg(sock, MSG_ERRQUEUE, verbose);

			/* Result format: seq, user txtime, hw txtime */
			if (verbose)
				fprintf(stdout, "%u\t%lu\t%lu\n",
					seq - 1,
					tx_timestampA,
					tx_timestampB);
		} else {
			/* Print 0 if txtimestamp failed to return in time,
			 * either indicating hwtstamp is not enabled OR
			 * packet failed to transmit.
			 */
			if (verbose)
				fprintf(stdout, "%u %lu 0\n",
					seq - 1, tx_timestampA);
		}
		fflush(stdout);
	}

	close(sock);
	return;
}


#define INTERVAL_MIN 500000
#define INTERVAL_MAX 5000000

void tx_thread_origin(struct user_opt *opt,
                      int *sockfd,
                      struct sockaddr_ll *sk_addr) {
	struct custom_payload *payload;
	struct timeval timeout;
	fd_set readfs, errorfs;
	uint64_t tx_timestamp;
	uint64_t tx_timestampA;
	uint64_t tx_timestampB;
	uint64_t looping_ts;
	struct timespec ts;
	tsn_packet *tsn_pkt;
	void *payload_ptr;
	int res;
	int ret;
	int verbose = opt->verbose;

	// int interval_ns = INTERVAL_MIN + rand() % (INTERVAL_MAX - INTERVAL_MIN + 1);
	int interval_ns = opt->interval_ns;
	int count = opt->frames_to_send;
	clockid_t clkid = opt->clkid;
	int sock = *sockfd;
	uint32_t seq = 1;

	/* Create packet template */
	tsn_pkt = alloca(opt->packet_size);
	setup_tsn_vlan_packet(opt, tsn_pkt);

	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	char control[CMSG_SPACE(sizeof(uint64_t))] = {};

	/* Construct the packet msghdr, CMSG and initialize packet payload */
	iov.iov_base = &tsn_pkt->vlan_prio;
	iov.iov_len = (size_t) opt->packet_size - 14;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = sk_addr;
	msg.msg_namelen = sizeof(struct sockaddr_ll);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_TXTIME;
	cmsg->cmsg_len = CMSG_LEN(sizeof(uint64_t));

	/* CMSG end? */

	uint64_t basetime = (opt->basetime == 0) ? get_time_sec(clkid) + (NSEC_PER_SEC * 2) :
											 ((get_time_nanosec(clkid) - opt->basetime) / (uint64_t)opt->interval_ns + (uint64_t)10) * (uint64_t)opt->interval_ns + opt->basetime - (uint64_t)opt->offset_ns;
	looping_ts = basetime + opt->offset_ns;
	looping_ts -= opt->early_offset_ns;
	ts.tv_sec = looping_ts / NSEC_PER_SEC;
	ts.tv_nsec = looping_ts % NSEC_PER_SEC;

	payload_ptr = (void *) (&tsn_pkt->payload);
	payload = (struct custom_payload *) payload_ptr;

	memcpy(&payload->tx_queue, &opt->socket_prio, sizeof(uint32_t));

	// while (count && !halt_tx_sig) {
	while (count) {
		ret = clock_nanosleep(clkid, TIMER_ABSTIME, &ts, NULL);
		if (ret) {
			fprintf(stderr, "Error: failed to sleep %d: %s", ret, strerror(ret));
			break;
		}

		tx_timestampA = get_time_nanosec(CLOCK_REALTIME);
		memcpy(&payload->seq, &seq, sizeof(uint32_t));
		memcpy(&payload->tx_timestampA, &tx_timestampA, sizeof(uint64_t));

		/* Update CMSG tx_timestamp and payload before sending */
		tx_timestamp = looping_ts + opt->early_offset_ns;
		*((__u64 *) CMSG_DATA(cmsg)) = tx_timestamp;

		ret = sendmsg(sock, &msg, 0);
		if (ret < 1)
			printf("sendmsg failed: %m");

		looping_ts += interval_ns;
		ts.tv_sec = looping_ts / NSEC_PER_SEC;
		ts.tv_nsec = looping_ts % NSEC_PER_SEC;
		// interval_ns = INTERVAL_MIN + rand() % (INTERVAL_MAX - INTERVAL_MIN + 1);
		// printf("interval = %d\n", interval_ns);

		count--;
		seq++;

		if (opt->enable_hwts) {
			//Note: timeout is duration not timestamp
			timeout.tv_usec = 2000;
			FD_ZERO(&readfs);
			FD_ZERO(&errorfs);
			FD_SET(sock, &readfs);
			FD_SET(sock, &errorfs);

			res = select(sock + 1, &readfs, 0, &errorfs, &timeout);
		} else {
			res = 0;
		}

		if (res > 0) {
			if (FD_ISSET(sock, &errorfs) && verbose)
				fprintf(stderr, "CSMG txtimestamp has error\n");

			tx_timestampB = extract_ts_from_cmsg(sock, MSG_ERRQUEUE, verbose);

			/* Result format: seq, user txtime, hw txtime */
			if (verbose)
				fprintf(stdout, "%u\t%lu\t%lu\n",
					seq - 1,
					tx_timestampA,
					tx_timestampB);
		} else {
			/* Print 0 if txtimestamp failed to return in time,
			 * either indicating hwtstamp is not enabled OR
			 * packet failed to transmit.
			 */
			if (verbose)
				fprintf(stdout, "%u %lu 0\n",
					seq - 1, tx_timestampA);
		}
		fflush(stdout);
	}

	close(sock);
	return;
}