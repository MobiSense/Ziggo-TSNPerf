#include <string.h>
#include <argp.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <libconfig.h>

#include "util.h"
#include "pcapReader.h"
#include "pcapSender.h"

#define MODE_TX 0
#define MODE_RX 1

#define TXMODE_PCAPTS 0
#define TXMODE_ONECYC 1
#define TXMODE_ORIGIN 2
#define TXMODE_BE     3

#define DEFAULT_PACKET_SIZE 1500
#define DEFAULT_TXTIME_OFFSET 0
#define DEFAULT_EARLY_OFFSET 100000
#define DEFAULT_PERIOD 1000000
#define DEFAULT_NUM_FRAMES 10000
#define DEFAULT_SOCKET_PRIORITY 0
#define DEFAULT_VLAN_PRIORITY 0
#define DEFAULT_ETHERNET_HEADER 0xb62c
const unsigned char DEFAULT_DST_MAC_ADDR[6] = { 0x00, 0x1b, 0x21, 0x76, 0xae, 0x75 };
const unsigned char DEFAULT_SRC_MAC_ADDR[6] = { 0x00, 0x1b, 0x21, 0x77, 0xac, 0xae };

// 程序的文档
static char doc[] = "Documentation is in TODO list.";

// 一个字符串，列出接受的选项的短名称
static char args_doc[] = "-i <interface> -f <pcap filename>";

// 选项的描述
static struct argp_option options[] = {
    {"interface", 'i', "IFNAME", 0, "interface name"},
    {"pcapfilename", 'f', "PCAPFILE", 0, "filename of pcap"},
    {"verbose",	'v',	0,	0, "print more infomation"},
    {"ziggo-analyse",	'z',	0,	0, "use ziggo for analysis or not"},
    {"configfilename", 'c', "CONFFILE", 0, "filename of configuration"},

    {0,0,0,0, "Mode:" },
	{"transmit",	't',	0,	0, "transmit only"},
	{"receive",	'r',	0,	0, "receive only"},

    {0,0,0,0, "TX Mode:" },
    {"acc-to-pcap-timestamp",	'p',	0,	0, "transimit packets according to timestamps in pcap file"},
    {"one-pkt-per-cycle",	'q',	0,	0, "transmit one packet per cycle, all packets are extracted from the pcap file"},
    {"original-iotg",	'g',	0,	0, "transmit one packet per cycle, all packets are constructed by code"},

    {0,0,0,0, "TX control:" },
	{"cycle-time",	'y',	"NSEC",	0, "tx period/interval/cycle-time\n"
					   "	Def: 100000ns | Min: 25000ns | Max: 50000000ns"},
    {"frames-to-send", 'n', "NUM",	0, "number of packets to transmit or receive\n"
					   "	Def: 1000 | Min: 1 | Max: 10000000"},
	{"dst-mac-addr",   'd', "MAC_ADDR",	0, "destination mac address\n"
						   "	Def: 22:bb:22:bb:22:bb"},

    {0,0,0,0, "LaunchTime/TBS-specific:\n(where base is the 0th ns of current second)" },
	{"transmit-offset",'o', "NSEC",	0, "packet txtime positive offset\n"
					   "	Def: 0ns | Min: 0ns | Max: 100000000ns"},
	{"early-offset",   'e', "NSEC",	0, "early execution negative offset\n"
					   "	Def: 100000ns | Min: 0ns | Max: 10000000ns"},
    {0}
};

// 解析一个选项时调用的函数
static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct user_opt *opt = state->input;
    int len = 0;
	char *str_end = NULL;
	errno = 0;
	long res = 0;
    int ret;
    
    switch (key) {
        case 'i':
            opt->ifname = strdup(arg);
            break;
        case 'f':
            opt->pcapfilename = strdup(arg);
            break;
        case 'c':
            opt->configfilename = strdup(arg);
            break;
        case 'v':
            opt->verbose = 1;
            break;
        case 'z':
            opt->ziggo_analysis = 1;
            break;
        case 't':
		    opt->mode = MODE_TX;
		    break;
	    case 'r':
            opt->mode = MODE_RX;
		    break;
        case 'p':
		    opt->tx_mode = TXMODE_PCAPTS;
		    break;
	    case 'q':
            opt->tx_mode = TXMODE_ONECYC;
		    break;
        case 'g':
            opt->tx_mode = TXMODE_ORIGIN;
		    break;
        case 'y':
            len = strlen(arg);
            res = strtol((const char *)arg, &str_end, 10);
            if (errno || res < 25000 || res > 50000000 || str_end != &arg[len])
                exit_with_error("Invalid cycle time. Check --help");
            opt->interval_ns = (uint32_t)res;
            break;
	    case 'n':
            len = strlen(arg);
            res = strtol((const char *)arg, &str_end, 10);
            if (errno || res < 1 || res > 10000000 || str_end != &arg[len])
                exit_with_error("Invalid number of frames to send. Check --help");
            opt->frames_to_send = (uint32_t)res;
            break;
        case 'o':
            len = strlen(arg);
            res = strtol((const char *)arg, &str_end, 10);
            if (errno || res < 0 || res > 100000000 || str_end != &arg[len])
                exit_with_error("Invalid offset. Check --help");
            opt->offset_ns = (uint32_t)res;
            break;
        case 'e':
            len = strlen(arg);
            res = strtol((const char *)arg, &str_end, 10);
            if (errno || res  < 0 || res > 10000000 || str_end != &arg[len])
                exit_with_error("Invalid early offset. Check --help");
            opt->early_offset_ns = (uint32_t)res;
            break;
        case 'd':
            ret = sscanf(arg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &opt->dst_mac_addr[0], &opt->dst_mac_addr[1], &opt->dst_mac_addr[2],
                        &opt->dst_mac_addr[3], &opt->dst_mac_addr[4], &opt->dst_mac_addr[5]);
            if (ret != 6)
                exit_with_error("Invalid destination MAC addr. Check --help");
        case ARGP_KEY_ARG:
            // 处理非选项参数
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

// argp结构体，用于将前面定义的信息绑定起来
static struct argp argp = {options, parse_opt, args_doc, doc};


void read_configuration_from_file(char* filename, struct user_opt* opt) {
    config_t cfg;
    config_init(&cfg);

    if (!config_read_file(&cfg, filename)) {
        fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
                config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        exit(EXIT_FAILURE);
    }

    int config_bool_data;
    int config_int_data;
    long long config_int64_data;
    const char* config_string_data;

    if (config_lookup_int(&cfg, "mode", &config_int_data)) {
        if (config_int_data != 0 && config_int_data != 1) {
            exit_with_error("Unsupported mode!")
        }
        opt->mode = config_int_data == 0 ? MODE_TX : MODE_RX;
    }

    if (config_lookup_int(&cfg, "tx-mode", &config_int_data)) {
        if (config_int_data < 0 || config_int_data > 3) {
            exit_with_error("Unsupported tx mode!")
        }
        opt->tx_mode = config_int_data < 2 ? (config_int_data == 0 ? TXMODE_PCAPTS : TXMODE_ONECYC) :
                                             (config_int_data == 2 ? TXMODE_ORIGIN : TXMODE_BE);
    }

    if (config_lookup_bool(&cfg, "verbose", &config_bool_data)) {
        opt->verbose = config_bool_data ? 1 : 0;
    }

    if (config_lookup_bool(&cfg, "use-ziggo-analysis", &config_bool_data)) {
        opt->ziggo_analysis = config_bool_data ? 1 : 0;
    }

    if (config_lookup_string(&cfg, "pcap-filename", &config_string_data)) {
        opt->pcapfilename = strdup(config_string_data);
    }

    if (config_lookup_string(&cfg, "interface", &config_string_data)) {
        opt->ifname = strdup(config_string_data);
    }

    if (config_lookup_string(&cfg, "dmac", &config_string_data)) {
        int ret = sscanf(config_string_data, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                         &opt->dst_mac_addr[0], &opt->dst_mac_addr[1], &opt->dst_mac_addr[2],
                         &opt->dst_mac_addr[3], &opt->dst_mac_addr[4], &opt->dst_mac_addr[5]);
        if (ret != 6) exit_with_error("Invalid destination MAC addr.");
    }

    if (config_lookup_string(&cfg, "smac", &config_string_data)) {
        int ret = sscanf(config_string_data, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                         &opt->src_mac_addr[0], &opt->src_mac_addr[1], &opt->src_mac_addr[2],
                         &opt->src_mac_addr[3], &opt->src_mac_addr[4], &opt->src_mac_addr[5]);
        if (ret != 6) exit_with_error("Invalid source MAC addr.");
    }

    if (config_lookup_int(&cfg, "ethertype", &config_int_data)) {
        opt->eth_hdr = (uint16_t)config_int_data;
    }

    if (config_lookup_int(&cfg, "socket-priority", &config_int_data))
        opt->socket_prio = config_int_data;
    if (config_lookup_int(&cfg, "vlan-priority", &config_int_data))
        opt->vlan_prio = (uint8_t)config_int_data;
    if (config_lookup_int(&cfg, "offset", &config_int_data))
        opt->offset_ns = config_int_data;
    if (config_lookup_int(&cfg, "early-offset", &config_int_data))
        opt->early_offset_ns = config_int_data;


    if (config_lookup_bool(&cfg, "use-launchtime", &config_bool_data))
        opt->enable_txtime = config_bool_data ? 1 : 0;
    if (config_lookup_int64(&cfg, "basetime", &config_int64_data))
        opt->basetime = (uint64_t)config_int64_data;

    if (config_lookup_int(&cfg, "packet-size", &config_int_data))
        opt->packet_size = config_int_data;
    if (config_lookup_int(&cfg, "packets-to-send", &config_int_data))
        opt->frames_to_send = config_int_data;
    if (config_lookup_int(&cfg, "interval", &config_int_data))
        opt->interval_ns = config_int_data;


    config_destroy(&cfg);
}

int main(int argc, char *argv[]) {
    struct user_opt opt;

    opt.mode = -1;
    opt.tx_mode = TXMODE_PCAPTS;
    opt.ziggo_analysis = 0;
    opt.eth_hdr = DEFAULT_ETHERNET_HEADER;
    opt.ifname = NULL;
    opt.pcapfilename = NULL;
    opt.configfilename = NULL;
    opt.offset_ns = DEFAULT_TXTIME_OFFSET;
    opt.early_offset_ns = DEFAULT_EARLY_OFFSET;
    opt.basetime = 0;
    // opt.basetime = 1684559640000000100L;
    memcpy(opt.dst_mac_addr, DEFAULT_DST_MAC_ADDR, sizeof(unsigned char) * 6);
    memcpy(opt.src_mac_addr, DEFAULT_SRC_MAC_ADDR, sizeof(unsigned char) * 6);
    opt.enable_txtime = 1;
    opt.clkid = CLOCK_REALTIME;
    // opt.clkid = CLOCK_TAI;
    opt.socket_prio = DEFAULT_SOCKET_PRIORITY;
    opt.vlan_prio = DEFAULT_VLAN_PRIORITY;

    opt.packet_size = DEFAULT_PACKET_SIZE;
    opt.frames_to_send = DEFAULT_NUM_FRAMES;
    opt.interval_ns = DEFAULT_PERIOD;
    opt.enable_hwts = 0;

    argp_parse(&argp, argc, argv, 0, 0, &opt);

    if (opt.configfilename) {
        printf("configuration file is %s\n", opt.configfilename);
        read_configuration_from_file(opt.configfilename, &opt);
    }

    printf(opt.mode == MODE_TX ? "TX mode\n" : "RX mode\n");
    printf(opt.tx_mode == TXMODE_PCAPTS ? "TX-MODE: send one pcap's pkt according to ts in pcap\n" : 
          (opt.tx_mode == TXMODE_ONECYC ? "TX-MODE: send one pcap's pkt per cycle\n" : 
          (opt.tx_mode == TXMODE_ORIGIN ? "TX-MODE: send one contructed pkt per cycle\n" :
                                          "TX-MODE: best effort\n")) );

    printf("Print %s infomation.\n", opt.verbose ? "MORE" : "LESS");
    printf(opt.ziggo_analysis ? "Use Ziggo Analyze\n" : "Use Intel Analyze\n");

    printf("pcap is %s\n", opt.pcapfilename);
    printf("interface is %s\n", opt.ifname);

    printf("source mac: %x:%x:%x:%x:%x:%x\n", opt.src_mac_addr[0], opt.src_mac_addr[1], opt.src_mac_addr[2],
                                              opt.src_mac_addr[3], opt.src_mac_addr[4], opt.src_mac_addr[5]);
    printf("destination mac: %x:%x:%x:%x:%x:%x\n", opt.dst_mac_addr[0], opt.dst_mac_addr[1], opt.dst_mac_addr[2],
                                                   opt.dst_mac_addr[3], opt.dst_mac_addr[4], opt.dst_mac_addr[5]);
    printf("ethertype = 0x%x\n", opt.eth_hdr);

    printf("socket priority is %u\n", opt.socket_prio);
    printf("vlan priority is %u\n", opt.vlan_prio);
    printf("offset is %dns\n", opt.offset_ns);
    printf("early offset is %dns\n", opt.early_offset_ns);

    printf("%s launchtime\n", opt.enable_txtime ? "Enable" : "Disable");
    printf("basetime is %lu\n", opt.basetime);

    printf("packet size is %dByte\n", opt.packet_size);
    printf("num packets to transmit is %d\n", opt.frames_to_send);
    printf("cycle time is %dns\n", opt.interval_ns);
    
    if (!opt.ifname)
		exit_with_error("Please specify interface using -i\n");

    opt.ifindex = if_nametoindex(opt.ifname);
	if (!opt.ifindex) {
		fprintf(stderr, "ERROR: interface \"%s\" do not exist\n", opt.ifname);
		exit(EXIT_FAILURE);
	}

    struct sockaddr_ll sk_addr = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_8021Q),
        .sll_halen = ETH_ALEN,
    };
    int sockfd;

    ts_log_start();

    switch (opt.mode) {
    case MODE_TX:

        struct pcap_reader* reader = NULL;

        // init tx socket
        init_tx_socket(&opt, &sockfd, &sk_addr);

        switch (opt.tx_mode)
        {
        case TXMODE_PCAPTS:
            
            // read pcap file
            reader = initPcapReader(opt.pcapfilename);
            while (next_packet(reader)) { }
            printf("Total %d packets\n", reader->packet_count);

            // start transmitting
            tx_thread(reader, &opt, &sockfd, &sk_addr);

            break;
        case TXMODE_ONECYC:

            // read pcap file
            reader = initPcapReader(opt.pcapfilename);
            while (next_packet(reader)) { }
            printf("Total %d packets\n", reader->packet_count);

            // start transmitting
            tx_periodically_thread(reader, &opt, &sockfd, &sk_addr);

            break;
        case TXMODE_ORIGIN:
            tx_thread_origin(&opt, &sockfd, &sk_addr);
            break;
        case TXMODE_BE:
            tx_thread_besteffort(&opt, &sockfd, &sk_addr);
            break;
        default:
            exit_with_error("Unknown tx mode");
            break;
        }
        freePcapReader(reader);
        break;
    
    case MODE_RX:
        break;
    default:
        break;
    }

    ts_log_stop();
    close(sockfd);

    return 0;
}