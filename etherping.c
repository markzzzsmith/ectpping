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

#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>



/*
 * ECTP frames are of type 0x9000
 */
#define ETH_P_ECTP 0x9000


/*
 * Function  Prototypes
 */

void debug_fn_name(const char *s);

void tx_thread(void);

void rx_thread(void);

enum OPEN_RX_SKT {
	OPEN_RX_SKT_GOOD,
	OPEN_RX_SKT_BADSOCKET, 		/* socket() call failed */
	OPEN_RX_SKT_BADIFINDEX,		/* supplied ifindex invalid */
};
enum OPEN_RX_SKT open_rx_socket(int *sockfd, const int rx_ifindex);

void print_rxed_dgrams(int *sockfd);

void rx_new_dgram(int *sockfd, unsigned char *pkt_buf,
	const unsigned int pkt_buf_sz, unsigned char *pkt_type,
	unsigned int *pkt_len, unsigned char *srcmac);

enum CLOSE_RX_SKT {
	CLOSE_RX_SKT_GOOD,
	CLOSE_RX_SKT_BAD,
};
enum CLOSE_RX_SKT close_rx_socket(int *sockfd);


/*
 * Functions
 */
int main(int argc, char *argv[])
{
	pthread_t tx_thread_hdl, rx_thread_hdl;


	/*
	 * Start threads
	 */
	pthread_create(&tx_thread_hdl, NULL, (void *)tx_thread, NULL);
	pthread_create(&rx_thread_hdl, NULL, (void *)rx_thread, NULL);


	/*
	 * Stop program exiting until threads stop
	 */
	pthread_join(tx_thread_hdl, NULL);
	pthread_join(rx_thread_hdl, NULL);

	return 0;

}

/*
 * Function to print the name of the calling function
 *
 * e.g. debug_fn_name(__func__)
 */
void debug_fn_name(const char *s)
{


#ifdef DEBUG
	printf("%s()\n", s);
#endif

}


void tx_thread(void)
{


	debug_fn_name(__func__);

}


void rx_thread(void)
{
	int sockfd;


	debug_fn_name(__func__);

	open_rx_socket(&sockfd, 10);

	print_rxed_dgrams(&sockfd);

	close_rx_socket(&sockfd);

}


/*
 * Opens the receive socket used by the rx thread
 */
enum OPEN_RX_SKT open_rx_socket(int *sockfd, const int rx_ifindex)
{
	struct sockaddr_ll sa_ll;


	debug_fn_name(__func__);

	*sockfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ECTP));
	if (*sockfd == -1) {
		return OPEN_RX_SKT_BADSOCKET;
	}

	memset(&sa_ll, 0, sizeof(sa_ll));
	sa_ll.sll_family = PF_PACKET;
	sa_ll.sll_ifindex = rx_ifindex;
	if ( bind(*sockfd, (struct sockaddr *) &sa_ll, sizeof(sa_ll)) != 0) 
		return OPEN_RX_SKT_BADIFINDEX;

	/* if we get here, all's good */
	return OPEN_RX_SKT_GOOD;

}


/*
 * Wait for incoming ECTP datagrams, and print their details when received
 */
void print_rxed_dgrams(int *sockfd)
{
	unsigned char pkt_buf[65536];
	unsigned char rxed_pkt_type;
	unsigned int rxed_pkt_len;
	unsigned char srcmac[ETH_ALEN];

	int i,j;


	debug_fn_name(__func__);


	for (i = 0; i < 10; i++) {

		rx_new_dgram(sockfd, pkt_buf, sizeof(pkt_buf), &rxed_pkt_type,
		&rxed_pkt_len, srcmac);

		switch (rxed_pkt_type) {
		case PACKET_HOST:
			printf("PACKET_HOST\n");
			break;
		case PACKET_BROADCAST:
			printf("PACKET_BROADCAST\n");
			break;
		case PACKET_MULTICAST:
			printf("PACKET_MULTICAST\n");
                        break;
		case PACKET_OTHERHOST:
			printf("PACKET_OTHERHOST\n");
                        break;

		}

	}

}


/*
 * Waits to receive a new ECTP datagram
 */
void rx_new_dgram(int *sockfd, unsigned char *pkt_buf,
	const unsigned int pkt_buf_sz, unsigned char *pkt_type,
	unsigned int *pkt_len, unsigned char *srcmac)
{
	struct sockaddr_ll sa_ll;
	unsigned int sa_ll_len;


	memset(pkt_buf, 0, pkt_buf_sz);

	sa_ll_len = sizeof(sa_ll);

	*pkt_len = recvfrom(*sockfd, pkt_buf, pkt_buf_sz,
		0, (struct sockaddr *) &sa_ll,
		(socklen_t *) &sa_ll_len );

	memcpy(srcmac, sa_ll.sll_addr, ETH_ALEN);

	*pkt_type = sa_ll.sll_pkttype;	
	
}



/*
 * Close the receive socket
 */
enum CLOSE_RX_SKT close_rx_socket(int *sockfd)
{


	debug_fn_name(__func__);

	if (close(*sockfd) == -1) 
		return CLOSE_RX_SKT_BAD;

	/* all's good if we get here */
	return CLOSE_RX_SKT_GOOD;

}
