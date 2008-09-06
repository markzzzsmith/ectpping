/*
 *	etherping
 *	~~~~~~~~~
 *
 *
 *
 *
 */

/* #define DEBUG 1 */
#define DEBUG 1 


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
	int ifindex;
	uint8_t srcmac[ETH_ALEN];
	uint8_t dstmac[ETH_ALEN];
};


/*
 * Program options in external user format
 */
struct program_options {
	char iface[IFNAMSIZ];
	enum { ucast, mcast, bcast } dst_type;
	char *uc_dst_str; /* mac address or /etc/ethers hostname */
};


/*
 * Arguments passed to the TX thread
 */
struct tx_thread_arguments {
	struct program_parameters *prog_parms;
	int *tx_sockfd;
};


/*
 *
 */
struct rx_thread_arguments {
	struct program_parameters *prog_parms;
	int *rx_sockfd;
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


void print_prog_parms(const struct program_parameters *prog_parms);

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

void tx_thread(struct tx_thread_arguments *tx_thread_args);

void rx_thread(struct rx_thread_arguments *rx_thread_args);

void print_rxed_frames(int *rx_sockfd);

void rx_new_frame(int *sockfd,
		  unsigned char *pkt_buf,
		  const unsigned int pkt_buf_sz,
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


	debug_fn_name(__func__);

	get_prog_parms(argc, argv, &prog_parms);

	print_prog_parms(&prog_parms);

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
 * Routine to print program parameters
 */
void print_prog_parms(const struct program_parameters *prog_parms)
{
	char pmacbuf[ENET_PADDR_MAXSZ];


	printf("prog_parms->ifindex = %d\n", prog_parms->ifindex);

	enet_ntop(prog_parms->srcmac, ENET_NTOP_UNIX, pmacbuf,
		sizeof(pmacbuf));
	printf("prog_parms->srcmac = %s\n", pmacbuf);

	enet_ntop(prog_parms->dstmac, ENET_NTOP_UNIX, pmacbuf,
		sizeof(pmacbuf));
	printf("prog_parms->dstmac = %s\n", pmacbuf);

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

	while ( (opt = getopt(argc, argv, "i:ab")) != -1) {
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
 * ECTP frame sender thread
 */
void tx_thread(struct tx_thread_arguments *tx_thread_args)
{


	debug_fn_name(__func__);

	while (quit_program == 0) {
		printf("emit ECTP frame\n");
		sleep(5);
	}

}


/*
 * ECTP frame receiver thread
 */
void rx_thread(struct rx_thread_arguments *rx_thread_args)
{


	debug_fn_name(__func__);

	print_rxed_frames(rx_thread_args->rx_sockfd);

	return;

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
 * Wait for incoming ECTP frames, and print their details when received
 */
void print_rxed_frames(int *rx_sockfd)
{
	unsigned char pkt_buf[65536];
	unsigned char rxed_pkt_type;
	unsigned int rxed_pkt_len;
	uint8_t srcmac[ETH_ALEN];
	char srcmacpbuf[ENET_PADDR_MAXSZ];
	fd_set select_fd_set;
	struct timeval select_tout;
	int select_result;


	debug_fn_name(__func__);


	while (quit_program == 0) {

		FD_ZERO(&select_fd_set);
		FD_SET(*rx_sockfd, &select_fd_set);

		select_tout.tv_sec = 0;
		select_tout.tv_usec = 100000; 

		/* need to error check select result */
		select_result = select(*rx_sockfd+1, &select_fd_set, NULL,
			NULL, &select_tout);

		if (select_result > 0) {
		
			rx_new_frame(rx_sockfd, pkt_buf, sizeof(pkt_buf),
				&rxed_pkt_type, &rxed_pkt_len, srcmac);

			switch (rxed_pkt_type) {
			case PACKET_HOST:
				printf("PACKET_HOST, ");
				break;
			case PACKET_BROADCAST:
				printf("PACKET_BROADCAST, ");
				break;
			case PACKET_MULTICAST:
				printf("PACKET_MULTICAST, ");
				break;
			case PACKET_OTHERHOST:
				printf("PACKET_OTHERHOST, ");
				break;
			}

			enet_ntop(srcmac, ENET_NTOP_UNIX, srcmacpbuf,
				sizeof(srcmacpbuf));
			printf("Packet source: %s, ", srcmacpbuf);
	
			printf("Packet length: %d\n", rxed_pkt_len);

		}

	}

}


/*
 * Receive a pending ECTP frame
 */
void rx_new_frame(int *rx_sockfd,
		  unsigned char *pkt_buf,
		  const unsigned int pkt_buf_sz,
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
		MSG_DONTWAIT, (struct sockaddr *) &sa_ll,
		(socklen_t *) &sa_ll_len );

	memcpy(srcmac, sa_ll.sll_addr, ETH_ALEN);

	*pkt_type = sa_ll.sll_pkttype;	
	
}


/*
 * print the received ECTP frame
 */
void print_rxed_ectp_frame(unsigned char *pkt_buf,
			   const unsigned int pkt_buf_sz,
			   unsigned char pkt_type,
			   unsigned int pkt_len,
			   uint8_t *srcmac)
{




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
