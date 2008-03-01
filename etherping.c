/*
 *	etherping
 *	~~~~~~~~~
 *
 *
 *
 *
 */

/* #define DEBUG 1 */


#include <stdio.h>
#include <string.h>

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

#include "libenetaddr.h"


/*
 * ECTP frames are of type 0x9000
 */
#define ETH_P_ECTP 0x9000


/*
 * Struct defs
 */

/*
 * Program parameters in internal program format
 */
struct program_parameters {
	int ifindex;
};


/*
 * Program options in external user format
 */
struct program_options {
	char iface[IFNAMSIZ];
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
enum GET_PROG_PARMS get_prog_parms(
				const int argc,
				char *argv[],
				struct program_parameters *prog_parms);

enum GET_CLI_OPTS {
	GET_CLI_OPTS_GOOD,
	GET_CLI_OPTS_BAD
};
enum GET_CLI_OPTS get_cli_opts(
				const int argc,
				char *argv[],
				struct program_options *prog_opts);


enum PROCESS_PROG_OPTS {
	PROCESS_PROG_OPTS_GOOD,
	PROCESS_PROG_OPTS_BAD
};
enum PROCESS_PROG_OPTS process_prog_opts(
				struct program_options *prog_opts,
				struct program_parameters *prog_parms);

unsigned int get_ifindex(char iface[IFNAMSIZ]);

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

void prepare_thread_args(
				struct tx_thread_arguments *tx_thread_args,
				struct rx_thread_arguments *rx_thread_args,
				struct program_parameters *prog_parms,
				int *tx_sockfd,
				int *rx_sockfd);

void tx_thread(struct tx_thread_arguments *tx_thread_args);

void rx_thread(struct rx_thread_arguments *rx_thread_args);

void print_rxed_frames(int *rx_sockfd);

void rx_new_frame(
				int *sockfd,
				unsigned char *pkt_buf,
				const unsigned int pkt_buf_sz,
				unsigned char *pkt_type,
				unsigned int *pkt_len,
				unsigned char *srcmac);

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

	quit_program = 1;

	pthread_cancel(tx_thread_hdl);

}


/*
 * Routine to collect program parameters from various sources e.g. cli
 * options, .rc file
 */
enum GET_PROG_PARMS get_prog_parms(
	const int argc,
	char *argv[],
	struct program_parameters *prog_parms)
{
	struct program_options prog_opts;


	debug_fn_name(__func__);

	memset(&prog_opts, 0, sizeof(prog_opts));

	get_cli_opts(argc, argv, &prog_opts);

	process_prog_opts(&prog_opts, prog_parms);

	return GET_PROG_PARMS_GOOD;

}


/*
 * Routine to collect program options from *argv[];
 */
enum GET_CLI_OPTS get_cli_opts(
				const int argc,
				char *argv[],
				struct program_options *prog_opts)
{
	int opt;


	debug_fn_name(__func__);

	while ( (opt = getopt(argc, argv, "i:")) != -1) {
		switch (opt) {
		case 'i':
			strncpy(prog_opts->iface, optarg, IFNAMSIZ);
			prog_opts->iface[IFNAMSIZ-1] = 0;
			break;
		}
	}

	return GET_CLI_OPTS_GOOD;


}


/*
 * Routine to convert collected program options into internal program
 * parameters
 */
enum PROCESS_PROG_OPTS process_prog_opts(
				struct program_options *prog_opts,
				struct program_parameters *prog_parms)
{
	int i;


	debug_fn_name(__func__);

	memset(prog_parms, 0, sizeof(struct program_parameters));

	i = get_ifindex(prog_opts->iface);
	if (i)
		prog_parms->ifindex = i;
	else
		return PROCESS_PROG_OPTS_BAD;

	return PROCESS_PROG_OPTS_GOOD;

}


/*
 * Routine to get the ifindex of the supplied interface name
 */
unsigned int get_ifindex(char iface[IFNAMSIZ])
{
	int sockfd;
	struct ifreq ifr;
	int ifindex;


	debug_fn_name(__func__);

	sockfd = socket(PF_PACKET, SOCK_RAW, 0);
	if (sockfd == -1)
		return 0;

	memset(&ifr, 0, sizeof(struct ifreq));

	strncpy(ifr.ifr_name, iface, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ-1] = 0;

	ifindex = ioctl(sockfd, SIOCGIFINDEX, &ifr);

	if (close(sockfd) == -1)
		return 0;
	
	if (ifindex != -1)
		return ifr.ifr_ifindex;
	else
		return 0;


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
void prepare_thread_args(
				struct tx_thread_arguments *tx_thread_args,
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

	*tx_sockfd = socket(PF_PACKET, SOCK_DGRAM, 0);
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

	*rx_sockfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ECTP));
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
 * Wait for incoming ECTP framess, and print their details when received
 */
void print_rxed_frames(int *rx_sockfd)
{
	unsigned char pkt_buf[65536];
	unsigned char rxed_pkt_type;
	unsigned int rxed_pkt_len;
	unsigned char srcmac[ETH_ALEN];
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
void rx_new_frame(
				int *rx_sockfd,
				unsigned char *pkt_buf,
				const unsigned int pkt_buf_sz,
				unsigned char *pkt_type,
				unsigned int *pkt_len,
				unsigned char *srcmac)
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
