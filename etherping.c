/*
 *	etherping
 *	~~~~~~~~~
 *
 *
 *
 *
 */

/* #define DEBUG 1 */
//#define DEBUG 1 


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ether.h>

#include "libenetaddr.h"
#include "libectp.h"


/*
 * Struct defs
 */

/*
 * Program parameters in internal program format
 */
struct program_parameters {
	char iface[IFNAMSIZ];
	int ifindex;
	uint8_t srcmac[ETH_ALEN];
	uint8_t dstmac[ETH_ALEN];
	uint8_t *ectp_user_data;
	unsigned int ectp_user_data_size;
	bool no_resolve;
};


/*
 * Program options in external user format
 */
struct program_options {
	char iface[IFNAMSIZ];
	enum { ucast, mcast, bcast } dst_type;
	char *uc_dst_str; /* mac address or /etc/ethers hostname string */
	bool no_resolve;
};


/*
 * Arguments passed to the TX thread
 */
struct tx_thread_arguments {
	struct program_parameters *prog_parms;
	int *tx_sockfd;
};


/*
 * Arguments passed to the RX thread
 */
struct rx_thread_arguments {
	struct program_parameters *prog_parms;
	int *rx_sockfd;
};


/*
 *
 */
struct etherping_payload {
	uint32_t seq_num;
	struct timeval tv;
};



/*
 * Function Prototypes
 */

void debug_fn_name(const char *s);

void setup_sigterm_hdlr(struct sigaction *sigterm_action);

void set_sigterm_hdlr(struct sigaction *sigterm_action);

void sigterm_hdlr(int signum);

enum GET_PROG_PARMS {
	GET_PROG_PARMS_GOOD,
	GET_PROG_PARMS_BADIFINDEX,
};
enum GET_PROG_PARMS get_prog_parms(const int argc,
				   char *argv[],
				   struct program_parameters *prog_parms);


void set_default_prog_opts(struct program_options *prog_opts);

enum GET_CLI_OPTS {
	GET_CLI_OPTS_GOOD,
	GET_CLI_OPTS_BAD
};
enum GET_CLI_OPTS get_cli_opts(const int argc,
			       char *argv[],
			       struct program_options *prog_opts);


enum PROCESS_PROG_OPTS {
	PROCESS_PROG_OPTS_GOOD,
	PROCESS_PROG_OPTS_BAD
};
enum PROCESS_PROG_OPTS process_prog_opts(const struct program_options
						*prog_opts,
					 struct program_parameters *prog_parms);


enum DO_IFREQ_IOCTL {
	DO_IFREQ_IOCTL_GOOD,
	DO_IFREQ_IOCTL_BADSOCKET,
	DO_IFREQ_IOCTL_BADIOCTL
};
enum DO_IFREQ_IOCTL do_ifreq_ioctl(const int ioctl_request,
				   const char iface[IFNAMSIZ],
				   struct ifreq *ifr);


enum GET_IFINDEX {
	GET_IFINDEX_GOOD,
	GET_IFINDEX_BADSOCKET,
	GET_IFINDEX_BADIFACE
};
enum GET_IFINDEX get_ifindex(const char iface[IFNAMSIZ], int *ifindex);


enum GET_IFMAC {
	GET_IFMAC_GOOD,
	GET_IFMAC_BADSOCKET,
	GET_IFMAC_BADIFACE
};
enum GET_IFMAC get_ifmac(const char iface[IFNAMSIZ],
			 unsigned char ifmac[ETH_ALEN]);

enum GET_IFMTU {
	GET_IFMTU_GOOD,
	GET_IFMTU_BADSOCKET,
	GET_IFMTU_BADIFACE
};
enum GET_IFMTU get_ifmtu(const char iface[IFNAMSIZ],
			 unsigned int *ifmtu);


void open_sockets(int *tx_sockfd, int *rx_sockfd, const int ifindex);


enum OPEN_TX_SKT {
	OPEN_TX_SKT_GOOD,
	OPEN_TX_SKT_BADSOCKET, 		/* socket() call failed */
	OPEN_TX_SKT_BADIFINDEX,		/* supplied ifindex invalid */
};
enum OPEN_TX_SKT open_tx_socket(int *sockfd, const int tx_ifindex);


enum OPEN_RX_SKT {
	OPEN_RX_SKT_GOOD,
	OPEN_RX_SKT_BADSOCKET, 		/* socket() call failed */
	OPEN_RX_SKT_BADIFINDEX,		/* supplied ifindex invalid */
};
enum OPEN_RX_SKT open_rx_socket(int *sockfd, const int rx_ifindex);


void prepare_thread_args(struct tx_thread_arguments *tx_thread_args,
			 struct rx_thread_arguments *rx_thread_args,
			 struct program_parameters *prog_parms,
			 int *tx_sockfd,
			 int *rx_sockfd);

void build_ectp_eth_hdr(const uint8_t *srcmac,
			const uint8_t *dstmac,
			struct ether_header *eth_hdr);

enum BUILD_ECTP_FRAME {
	BUILD_ECTP_FRAME_GOOD,
	BUILD_ECTP_FRAME_BADBUFSIZE,
	BUILD_ECTP_FRAME_MTUTOOSMALL,
	BUILD_ECTP_FRAME_NOMEM
};
enum BUILD_ECTP_FRAME build_ectp_frame(
				   const struct program_parameters *prog_parms,
				   uint8_t frame_buf[],
				   const unsigned int frame_buf_sz,
				   const uint8_t *prog_data,
				   const unsigned int prog_data_size,
				   unsigned int *ectp_frame_len);

void tx_thread(struct tx_thread_arguments *tx_thread_args);

void rx_thread(struct rx_thread_arguments *rx_thread_args);

enum ECTP_PKT_VALID {
	ECTP_PKT_VALID_GOOD,
	ECTP_PKT_VALID_TOOSMALL,
	ECTP_PKT_VALID_BADSKIPCOUNT,
	ECTP_PKT_VALID_BADMSGTYPE,
	ECTP_PKT_VALID_WRONGRCPTNUM
};
enum ECTP_PKT_VALID ectp_pkt_valid(const struct ectp_packet *ectp_pkt,
				   const unsigned int ectp_pkt_size,
				   const struct program_parameters *prog_parms,
				   uint8_t **ectp_data,
				   unsigned int *ectp_data_size);

void print_rxed_packet(const struct program_parameters *prog_parms,
		       const struct timeval *pkt_arrived,
		       const uint8_t *srcmac,
		       const unsigned int pkt_len,
		       const uint8_t *ectp_data,
		       const unsigned int ectp_data_size);

void process_rxed_frames(int *rx_sockfd,
			 const struct program_parameters *prog_parms);

void rx_new_packet(int *sockfd,
		  unsigned char *pkt_buf,
		  const unsigned int pkt_buf_sz,
		  struct timeval *pkt_arrived,
		  unsigned char *pkt_type,
		  unsigned int *pkt_len,
		  uint8_t *srcmac);

void close_sockets(int *tx_sockfd, int *rx_sockfd);

enum CLOSE_TX_SKT {
	CLOSE_TX_SKT_GOOD,
	CLOSE_TX_SKT_BAD,
};
enum CLOSE_TX_SKT close_tx_socket(int *tx_sockfd);


enum CLOSE_RX_SKT {
	CLOSE_RX_SKT_GOOD,
	CLOSE_RX_SKT_BAD,
};
enum CLOSE_RX_SKT close_rx_socket(int *rx_sockfd);


/*
 * Global Variables
 */

/*
 * Toggled by sigterm, indicating to rx thread to stop
 */
int quit_program;

/*
 * tx & rx thread handles
 */
pthread_t tx_thread_hdl;
pthread_t rx_thread_hdl;


/*
 * Functions
 */

int main(int argc, char *argv[])
{
	struct sigaction sigterm_action;
	struct program_parameters prog_parms;
	int tx_sockfd, rx_sockfd;
	struct tx_thread_arguments tx_thread_args;
	struct rx_thread_arguments rx_thread_args;
	unsigned char ectp_data[] =
		__BASE_FILE__ ", built " __TIMESTAMP__ ", using GCC version "
		__VERSION__;


	debug_fn_name(__func__);

	get_prog_parms(argc, argv, &prog_parms);

	prog_parms.ectp_user_data = ectp_data;
	prog_parms.ectp_user_data_size = sizeof(ectp_data);

	open_sockets(&tx_sockfd, &rx_sockfd, prog_parms.ifindex);

	prepare_thread_args(&tx_thread_args, &rx_thread_args, &prog_parms,
		&tx_sockfd, &rx_sockfd);

	setup_sigterm_hdlr(&sigterm_action);

	pthread_create(&tx_thread_hdl, NULL, (void *)tx_thread,
		&tx_thread_args);
	pthread_create(&rx_thread_hdl, NULL, (void *)rx_thread,
		&rx_thread_args);
	pthread_join(tx_thread_hdl, NULL);
	pthread_join(rx_thread_hdl, NULL);

	close_sockets(&tx_sockfd, &rx_sockfd);

	return 0;

}


/*
 * Function to print the name of the calling function
 *
 * e.g. debug_fn_name(__func__);
 */
void debug_fn_name(const char *s)
{


#ifdef DEBUG
	printf("%s()\n", s);
#endif

}


/*
 * Setup things needed for the sigterm handler
 */
void setup_sigterm_hdlr(struct sigaction *sigterm_action)
{


	debug_fn_name(__func__);

	quit_program = 0;
	set_sigterm_hdlr(sigterm_action);

}


/*
 * Replaces SIGTERM handler
 */
void set_sigterm_hdlr(struct sigaction *sigterm_action)
{


	debug_fn_name(__func__);

	sigterm_action->sa_handler = sigterm_hdlr;
	sigemptyset(&(sigterm_action->sa_mask));
	sigterm_action->sa_flags = 0;

	sigaction(SIGINT, sigterm_action, NULL);

}


/*
 * Called upon SIGTERM
 */
void sigterm_hdlr(int signum)
{


	debug_fn_name(__func__);

	if (quit_program) /* SIGTERM received twice, hard exit program */
		exit(0);

	quit_program = 1;

	pthread_cancel(tx_thread_hdl);

}


/*
 * Routine to collect program parameters from various sources e.g. cli
 * options, .rc file
 */
enum GET_PROG_PARMS get_prog_parms(const int argc,
				   char *argv[],
				   struct program_parameters *prog_parms)
{
	struct program_options prog_opts;


	debug_fn_name(__func__);

	set_default_prog_opts(&prog_opts);

	get_cli_opts(argc, argv, &prog_opts);

	process_prog_opts(&prog_opts, prog_parms);

	return GET_PROG_PARMS_GOOD;

}


/*
 * Set some reasonable program option defaults
 */ 
void set_default_prog_opts(struct program_options *prog_opts)
{
	char *default_iface = "eth0";


	debug_fn_name(__func__);

	memset(prog_opts, 0, sizeof(struct program_options));

	/* default interface */
	strncpy(prog_opts->iface, default_iface, IFNAMSIZ);
	prog_opts->iface[IFNAMSIZ-1] = '\0';

	prog_opts->dst_type = mcast;

	prog_opts->no_resolve = false;

}


/*
 * Routine to collect program options from *argv[];
 */
enum GET_CLI_OPTS get_cli_opts(const int argc,
			       char *argv[],
			       struct program_options *prog_opts)
{
	int opt;


	debug_fn_name(__func__);

	while ( (opt = getopt(argc, argv, "i:abn")) != -1) {
		switch (opt) {
		case 'i':
			strncpy(prog_opts->iface, optarg, IFNAMSIZ);
			prog_opts->iface[IFNAMSIZ-1] = 0;
			break;
		case 'a':
			/* reserved for listening on all interfaces
			 * (by setting ifindex on rx socket to 0) */
			break;
		case 'b':
			prog_opts->dst_type = bcast;
			break;
		case 'n':
			prog_opts->no_resolve = true;
			break;
		}
	}

	/* first non-opt is assumed to be dest mac addr */
	if (optind < argc) { 
		prog_opts->dst_type = ucast;
		prog_opts->uc_dst_str = argv[optind];
	}

	return GET_CLI_OPTS_GOOD;

}


/*
 * Routine to convert collected program options into internal program
 * parameters
 */
enum PROCESS_PROG_OPTS process_prog_opts(const struct program_options
						*prog_opts,
					 struct program_parameters *prog_parms)
{
	const uint8_t bcast_addr[ETH_ALEN] = { 0xff, 0xff, 0xff,
					       0xff, 0xff, 0xff };
	const uint8_t lc_mcaddr[ETH_ALEN] = ECTP_LA_MCADDR; 
					    


	debug_fn_name(__func__);

	memset(prog_parms, 0, sizeof(struct program_parameters));

	if (get_ifindex(prog_opts->iface, &prog_parms->ifindex)
		!= GET_IFINDEX_GOOD)
			return PROCESS_PROG_OPTS_BAD;

	if (get_ifmac(prog_opts->iface, prog_parms->srcmac)
		!= GET_IFMAC_GOOD)
			return PROCESS_PROG_OPTS_BAD;

	strncpy(prog_parms->iface, prog_opts->iface, IFNAMSIZ);
	prog_parms->iface[IFNAMSIZ-1] = '\0';

	switch (prog_opts->dst_type) {
	case ucast:
		if (ether_hostton(prog_opts->uc_dst_str,
			(struct ether_addr *)prog_parms->dstmac) == 0) {
			break;
		}
		if (enet_pton(prog_opts->uc_dst_str, prog_parms->dstmac) !=
			ENET_PTON_GOOD) {
			return PROCESS_PROG_OPTS_BAD;
		}
		break;
	case bcast:
		memcpy(prog_parms->dstmac, bcast_addr, ETH_ALEN);
		break;
	case mcast:
	default:
		memcpy(prog_parms->dstmac, lc_mcaddr, ETH_ALEN);
		break;
	}

	prog_parms->no_resolve = prog_opts->no_resolve;

	return PROCESS_PROG_OPTS_GOOD;

}


/*
 * Routine to perform the specified interface ioctl
 */
enum DO_IFREQ_IOCTL do_ifreq_ioctl(const int ioctl_request,
				   const char iface[IFNAMSIZ],
				   struct ifreq *ifr)
{
	int sockfd;
	int ioctlret;



	debug_fn_name(__func__);

	sockfd = socket(PF_PACKET, SOCK_DGRAM, 0);
	if (sockfd == -1)
		return DO_IFREQ_IOCTL_BADSOCKET;

	memset(ifr, 0, sizeof(struct ifreq));

	strncpy(ifr->ifr_name, iface, IFNAMSIZ);
	ifr->ifr_name[IFNAMSIZ-1] = 0;

	ioctlret = ioctl(sockfd, ioctl_request, ifr);

	if (close(sockfd) == -1)
		return DO_IFREQ_IOCTL_BADSOCKET;

	if (ioctlret == -1)
		return DO_IFREQ_IOCTL_BADIOCTL;
	else
		return DO_IFREQ_IOCTL_GOOD;

}


/*
 * Routine to get the ifindex of the supplied interface name
 */
enum GET_IFINDEX get_ifindex(const char iface[IFNAMSIZ], int *ifindex)
{
	struct ifreq ifr;


	debug_fn_name(__func__);

	if (do_ifreq_ioctl(SIOCGIFINDEX, iface, &ifr) == DO_IFREQ_IOCTL_GOOD) {
		*ifindex = ifr.ifr_ifindex;
		return GET_IFINDEX_GOOD;
	} else {
		return GET_IFINDEX_BADIFACE;
	}

}


/*
 * Routine to get the mac address for an interface
 */
enum GET_IFMAC get_ifmac(const char iface[IFNAMSIZ],
			 unsigned char ifmac[ETH_ALEN])
{
	struct ifreq ifr;


	debug_fn_name(__func__);

	if (do_ifreq_ioctl(SIOCGIFHWADDR, iface, &ifr) == DO_IFREQ_IOCTL_GOOD) {
		if (ifr.ifr_hwaddr.sa_family == ARPHRD_ETHER) {
			memcpy(ifmac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
			return GET_IFMAC_GOOD;
		} else {
			return GET_IFMAC_BADIFACE;
		}
	} else {
		return GET_IFMAC_BADIFACE;
	}

}


/*
 * Routine to get the MTU of the specified interface 
 */
enum GET_IFMTU get_ifmtu(const char iface[IFNAMSIZ],
			 unsigned int *ifmtu)
{
	struct ifreq ifr;


	debug_fn_name(__func__);


	if (do_ifreq_ioctl(SIOCGIFMTU, iface, &ifr) == DO_IFREQ_IOCTL_GOOD) {
		*ifmtu = ifr.ifr_mtu;
		return GET_IFMTU_GOOD;
	} else {
		return GET_IFMTU_BADIFACE;
	}



}


/*
 * Routine to open TX and RX PF_PACKET sockets
 */
void open_sockets(int *tx_sockfd, int *rx_sockfd, const int ifindex)
{


	debug_fn_name(__func__);

	open_tx_socket(tx_sockfd, ifindex);

	open_rx_socket(rx_sockfd, ifindex);

}


/*
 * Prepares the argument structures passed to the tx and rx threads
 */
void prepare_thread_args(struct tx_thread_arguments *tx_thread_args,
			 struct rx_thread_arguments *rx_thread_args,
			 struct program_parameters *prog_parms,
			 int *tx_sockfd,
			 int *rx_sockfd)
{


	debug_fn_name(__func__);

	tx_thread_args->prog_parms = prog_parms;
	tx_thread_args->tx_sockfd = tx_sockfd;

	rx_thread_args->prog_parms = prog_parms;
	rx_thread_args->rx_sockfd = rx_sockfd;

}


/*
 * Build the ectp frame ethernet header
 */
void build_ectp_eth_hdr(const uint8_t *srcmac,
			const uint8_t *dstmac,
			struct ether_header *eth_hdr)
{


	memcpy(eth_hdr->ether_shost, srcmac, ETH_ALEN);
	memcpy(eth_hdr->ether_dhost, dstmac, ETH_ALEN);

	eth_hdr->ether_type = htons(ETHERTYPE_LOOPBACK);

}


enum BUILD_ECTP_FRAME build_ectp_frame(
				   const struct program_parameters *prog_parms,
				   uint8_t frame_buf[],
				   const unsigned int frame_buf_sz,
				   const uint8_t *prog_data,
				   const unsigned int prog_data_size,
				   unsigned int *ectp_frame_len)
{
	unsigned int ifmtu;
	unsigned int ectp_pkt_len;
	unsigned int frame_payload_size;
	uint8_t *frame_payload;


	if (sizeof(struct ether_header) > frame_buf_sz)
		return BUILD_ECTP_FRAME_BADBUFSIZE;

	build_ectp_eth_hdr(prog_parms->srcmac, prog_parms->dstmac,
		(struct ether_header *)&frame_buf[0]);
	
	frame_payload_size = prog_data_size + prog_parms->ectp_user_data_size;

	ectp_pkt_len = ectp_calc_packet_size(1, frame_payload_size);

	if (ectp_pkt_len > (frame_buf_sz - ETH_HLEN))
		return BUILD_ECTP_FRAME_BADBUFSIZE;

	get_ifmtu(prog_parms->iface, &ifmtu);

	if (ectp_pkt_len > ifmtu)
		return BUILD_ECTP_FRAME_MTUTOOSMALL;

	frame_payload = malloc(frame_payload_size);
	if (frame_payload == NULL)
		return BUILD_ECTP_FRAME_NOMEM;

	memcpy(frame_payload, prog_data, prog_data_size);
	memcpy(&frame_payload[prog_data_size], prog_parms->ectp_user_data,
		prog_parms->ectp_user_data_size);

	ectp_build_packet(0, (struct ether_addr *)prog_parms->srcmac,
		1, getpid(), frame_payload, frame_payload_size,
		&frame_buf[ETH_HLEN], frame_buf_sz - ETH_HLEN, 0x00);

	*ectp_frame_len = ETH_HLEN + ectp_pkt_len;

	free(frame_payload);

	return BUILD_ECTP_FRAME_GOOD;

}


/*
 * ECTP frame sender thread
 */
void tx_thread(struct tx_thread_arguments *tx_thread_args)
{
	uint8_t tx_frame_buf[0xffff];
	unsigned int ectp_frame_len;
	struct etherping_payload eping_payload = {
		.seq_num = 0,
	};
	

	debug_fn_name(__func__);

	while (!quit_program) {

		usleep(1000000);

		gettimeofday(&eping_payload.tv, NULL);

		build_ectp_frame(tx_thread_args->prog_parms, tx_frame_buf,
			sizeof(tx_frame_buf), (uint8_t *)&eping_payload,
			sizeof(struct etherping_payload),
			&ectp_frame_len);

		send(*tx_thread_args->tx_sockfd, tx_frame_buf, ectp_frame_len,
			MSG_DONTWAIT);	

		eping_payload.seq_num++;

	}

}


/*
 * ECTP frame receiver thread
 */
void rx_thread(struct rx_thread_arguments *rx_thread_args)
{


	debug_fn_name(__func__);

	process_rxed_frames(rx_thread_args->rx_sockfd,
		rx_thread_args->prog_parms);

}


/*
 * Opens the transmit socket used by the tx thread
 */
enum OPEN_TX_SKT open_tx_socket(int *tx_sockfd, const int tx_ifindex)
{
	struct sockaddr_ll sa_ll;


	debug_fn_name(__func__);

	*tx_sockfd = socket(PF_PACKET, SOCK_RAW, 0);
	if (*tx_sockfd == -1)
		return OPEN_TX_SKT_BADSOCKET;

	memset(&sa_ll, 0, sizeof(sa_ll));
	sa_ll.sll_family = PF_PACKET;
	sa_ll.sll_ifindex = tx_ifindex;

	if ( bind(*tx_sockfd, (struct sockaddr *) &sa_ll, sizeof(sa_ll)) != 0) 
		return OPEN_TX_SKT_BADIFINDEX;

	/* if we get here, all's good */
	return OPEN_TX_SKT_GOOD;

}


/*
 * Opens the receive socket used by the rx thread
 */
enum OPEN_RX_SKT open_rx_socket(int *rx_sockfd, const int rx_ifindex)
{
	struct sockaddr_ll sa_ll;


	debug_fn_name(__func__);

	*rx_sockfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETHERTYPE_LOOPBACK));
	if (*rx_sockfd == -1)
		return OPEN_RX_SKT_BADSOCKET;

	memset(&sa_ll, 0, sizeof(sa_ll));
	sa_ll.sll_family = PF_PACKET;
	sa_ll.sll_ifindex = rx_ifindex;

	if ( bind(*rx_sockfd, (struct sockaddr *) &sa_ll, sizeof(sa_ll)) != 0) 
		return OPEN_RX_SKT_BADIFINDEX;

	/* if we get here, all's good */
	return OPEN_RX_SKT_GOOD;

}


/*
 * Validate the supplied ECTP packet, using the program parameters
 * to determine some of the validation tests
 */
enum ECTP_PKT_VALID ectp_pkt_valid(const struct ectp_packet *ectp_pkt,
				   const unsigned int ectp_pkt_size,
				   const struct program_parameters *prog_parms,
				   uint8_t **ectp_data,
				   unsigned int *ectp_data_size)
{
	unsigned int looklen;
	unsigned int skipcount;
	struct ectp_message *curr_ectp_msg;


	debug_fn_name(__func__);

	if (ectp_pkt_size < ECTP_PACKET_HDR_SZ)
		return ECTP_PKT_VALID_TOOSMALL;

	looklen = ECTP_PACKET_HDR_SZ;

	skipcount = ectp_get_skipcount(ectp_pkt);

	if (!ectp_skipc_basicchk_ok(skipcount, ectp_pkt_size))
		return ECTP_PKT_VALID_BADSKIPCOUNT;

	looklen += skipcount + ECTP_MSG_FUNC_SZ;

	if (looklen >= ectp_pkt_size)
		return ECTP_PKT_VALID_TOOSMALL;

	curr_ectp_msg = ectp_get_curr_msg_ptr(ectp_pkt);

	if (ectp_get_msg_type(curr_ectp_msg) != ECTP_RPLYMSG)
		return ECTP_PKT_VALID_BADMSGTYPE;

	looklen += sizeof(struct ectp_reply_message);

	if (looklen >= ectp_pkt_size)
		return ECTP_PKT_VALID_TOOSMALL;

	if(ectp_get_rplymsg_rcpt_num(curr_ectp_msg) != getpid())
		return ECTP_PKT_VALID_WRONGRCPTNUM;

	*ectp_data_size = ectp_pkt_size - looklen;

	*ectp_data = ectp_get_rplymsg_data_ptr(curr_ectp_msg);

	return ECTP_PKT_VALID_GOOD;

}


/*
 * Print data about received packet
 */
void print_rxed_packet(const struct program_parameters *prog_parms,
		       const struct timeval *pkt_arrived,
		       const uint8_t *srcmac,
		       const unsigned int pkt_len,
		       const uint8_t *ectp_data,
		       const unsigned int ectp_data_size)
{
	char srcmacpbuf[ENET_PADDR_MAXSZ];
	char srcmachost[1024]; /* see ether_ntoh.c in glibc for size */
	struct etherping_payload eping_payload;
	struct timeval tv_diff;


	memcpy(&eping_payload, ectp_data, sizeof(struct etherping_payload));
	timersub(pkt_arrived, &eping_payload.tv, &tv_diff);

	enet_ntop(srcmac, ENET_NTOP_UNIX, srcmacpbuf, ENET_PADDR_MAXSZ);

	if (!prog_parms->no_resolve) {
		if (ether_ntohost(srcmachost, (struct ether_addr *)srcmac) !=
			0)
			sprintf(srcmachost,"(unknown)");
		printf("%d bytes from %10s (%s): ectp_seq=%d time=%ld "
		       "us\n", pkt_len,
			srcmachost, srcmacpbuf, eping_payload.seq_num,
			tv_diff.tv_usec);

	} else {
		printf("%d bytes from %s: ectp_seq=%d time=%ld us\n",
			pkt_len, srcmacpbuf, eping_payload.seq_num,
			tv_diff.tv_usec);
	}

}


/*
 * Wait for incoming ECTP frames, and print their details when received
 */
void process_rxed_frames(int *rx_sockfd,
			 const struct program_parameters *prog_parms)
{
	unsigned char pkt_buf[0xffff];
	unsigned char rxed_pkt_type;
	unsigned int rxed_pkt_len;
	uint8_t srcmac[ETH_ALEN];
	uint8_t *ectp_data;
	unsigned int ectp_data_size;
	struct timeval pkt_arrived;


	debug_fn_name(__func__);


	while (!quit_program) {

		rx_new_packet(rx_sockfd, pkt_buf, sizeof(pkt_buf),
			&pkt_arrived, &rxed_pkt_type, &rxed_pkt_len,
			srcmac);

		if (ectp_pkt_valid((struct ectp_packet *)pkt_buf,
			rxed_pkt_len, prog_parms, &ectp_data,
			&ectp_data_size) ==
			ECTP_PKT_VALID_GOOD) {

			print_rxed_packet(prog_parms, &pkt_arrived,
				srcmac, rxed_pkt_len, ectp_data,
				ectp_data_size);

		}

	}

}


/*
 * Receive a pending ECTP frame
 */
void rx_new_packet(int *rx_sockfd,
		  unsigned char *pkt_buf,
		  const unsigned int pkt_buf_sz,
		  struct timeval *pkt_arrived,
		  unsigned char *pkt_type,
		  unsigned int *pkt_len,
		  uint8_t *srcmac)
{
	struct sockaddr_ll sa_ll;
	unsigned int sa_ll_len;


	debug_fn_name(__func__);

	memset(pkt_buf, 0, pkt_buf_sz);

	sa_ll_len = sizeof(sa_ll);

	*pkt_len = recvfrom(*rx_sockfd, pkt_buf, pkt_buf_sz,
		0, (struct sockaddr *) &sa_ll,
		(socklen_t *) &sa_ll_len );

	ioctl(*rx_sockfd, SIOCGSTAMP, pkt_arrived);

	memcpy(srcmac, sa_ll.sll_addr, ETH_ALEN);

	*pkt_type = sa_ll.sll_pkttype;	
	
}


/*
 * Close tx & rx sockets
 */
void close_sockets(int *tx_sockfd, int *rx_sockfd)
{


	debug_fn_name(__func__);

	close_tx_socket(tx_sockfd);
	close_rx_socket(rx_sockfd);

}


/*
 * Close the transmit socket
 */
enum CLOSE_TX_SKT close_tx_socket(int *tx_sockfd)
{


	debug_fn_name(__func__);

	if (close(*tx_sockfd) == -1) 
		return CLOSE_TX_SKT_BAD;

	/* all's good if we get here */
	return CLOSE_TX_SKT_GOOD;

}


/*
 * Close the receive socket
 */
enum CLOSE_RX_SKT close_rx_socket(int *rx_sockfd)
{


	debug_fn_name(__func__);

	if (close(*rx_sockfd) == -1) 
		return CLOSE_RX_SKT_BAD;

	/* all's good if we get here */
	return CLOSE_RX_SKT_GOOD;

}
