#ifndef PCAPSENDER_H_
#define PCAPSENDER_H_

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <poll.h>

#include "util.h"
#include "pcapReader.h"

int init_tx_socket(struct user_opt *opt, int *sockfd, struct sockaddr_ll *sk_addr);
void tx_thread(struct pcap_reader*,
               struct user_opt *opt,
               int *sockfd,
               struct sockaddr_ll *sk_addr);
void tx_periodically_thread(struct pcap_reader*,
                            struct user_opt *opt,
                            int *sockfd,
                            struct sockaddr_ll *sk_addr);
void tx_thread_besteffort(struct user_opt *opt,
                          int *sockfd,
                          struct sockaddr_ll *sk_addr);
void tx_thread_origin(struct user_opt *opt,
                      int *sockfd,
                      struct sockaddr_ll *sk_addr);

#endif