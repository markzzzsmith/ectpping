#ifndef __libectp_h__
#define __libectp_h__

#include <stdint.h>
#include <stdbool.h>

#include <net/ethernet.h>


/*
 *
 *	Ethernet Configuration Testing Protocol (ECTP) defines and structures
 *
 */

/*
 * ECTP loopback assistance multicast address 
 */
#define ECTP_LA_MCADDR { 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00 }


/*
 * ECTP protocol header sizes in octets
 */

/*
 * ECTP header size in octets (i.e. skipcount field)
 */
enum {
	ECTP_PACKET_HDR_SZ	= 2,
};


/*
 * ECTP message function field size
 */ 
enum { 
	ECTP_MSG_FUNC_SZ	= 2,
};


/*
 * Forward Message size in octets (includes Function field)
 */
enum {
	ECTP_FWDMSG_SZ		= 8,
};


/*
 * Minimum Reply Message size in octets. (includes Function field))
 */
enum {
	ECTP_REPLYMSG_MINSZ	= 4,
};


/*
 * Minimum ECTP packet size (Must be the sum of the above :-) )
 */
enum {
	ECTP_PACKET_MIN_SZ	= 14,
};


/*
 * Function Code field values
 */

enum {
	ECTP_RPLYMSG		= 1,	/* Reply message */
	ECTP_FWDMSG		= 2,	/* Forward message */
};


/*
 * ECTP packet structures
 */


/*
 * ECTP common header - only consists of the single 2 octet skip count
 * field.
 *
 * note: skipcount is little endian, i.e. _not_ traditional big endian
 * network order - don't use traditional ntohs() or htons() functions
 * on it, because they won't work.
 */
struct ectp_packet_header {
        uint16_t skipcount; 
} __attribute__ ((packed));


/*
 * ECTP packet
 */
struct ectp_packet {
        struct ectp_packet_header hdr;
        uint8_t payload[];
} __attribute__ ((packed));


/*
 * ECTP Reply Message (minus Function Code field)
 */
struct ectp_reply_message {
        uint16_t rcpt_num;
        uint8_t data[];
} __attribute__ ((packed));


/*
 * ECTP Forward Message (minus Function Code field)
 */
struct ectp_forward_message {
        uint8_t fwdaddr[ETH_ALEN];
} __attribute__ ((packed));


/*
 * ECTP Message Header
 */
struct ectp_message_header {
        uint16_t func_code;
} __attribute__ ((packed));


/*
 * ECTP Message
 */
struct ectp_message {
        struct ectp_message_header hdr;
        union {
                struct ectp_forward_message fwd_msg;
                struct ectp_reply_message rply_msg;
        };
} __attribute__ ((packed));


/*
 * ECTP packet utility functions
 */

uint16_t ectp_htons(uint16_t i);

uint16_t ectp_ntohs(uint16_t i);

unsigned int ectp_get_skipcount(const struct ectp_packet *ectp_pkt);

void ectp_set_skipcount(struct ectp_packet *ectp_pkt,
			const unsigned int skipcount);

bool ectp_skipc_basicchk_ok(const unsigned int skipcount,
		   	   const unsigned int ectp_pkt_len);

struct ectp_message *ectp_get_msg_ptr(const unsigned int skipcount,
				      const struct ectp_packet
					*ectp_pkt);

struct ectp_message *ectp_get_curr_msg_ptr(const struct ectp_packet
						*ectp_pkt);

uint16_t ectp_get_msg_type(const struct ectp_message *ectp_msg);

void ectp_set_msg_type(struct ectp_message *ectp_msg, 
		       const uint16_t msg_type);

bool ectp_fwdaddr_ok(const uint8_t fwdaddr[ETH_ALEN]);

uint8_t *ectp_get_fwdaddr(const struct ectp_message *ectp_fwd_msg);

void ectp_set_fwdaddr(struct ectp_message *ectp_fwd_msg, 
		      const uint8_t fwdaddr[ETH_ALEN]);

void ectp_set_fwdmsg(struct ectp_message *ectp_fwd_msg,
		     const uint8_t fwdaddr[ETH_ALEN]);

void ectp_set_rplymsg_rcpt_num(struct ectp_message *ectp_rply_msg, 
			       const uint16_t rcpt_num);

uint16_t ectp_get_rplymsg_rcpt_num(const struct ectp_message *ectp_rply_msg);

void ectp_set_rplymsg_hdr(struct ectp_message *ectp_rply_msg,
			  const uint16_t rcpt_num);

void ectp_set_rplymsg_data(struct ectp_message *ectp_rply_msg, 
			   const uint8_t *data,
			   const unsigned int data_size);

uint8_t *ectp_get_rplymsg_data_ptr(struct ectp_message *ectp_rply_msg);


void ectp_inc_skipcount(struct ectp_packet *ectp_pkt);

unsigned int ectp_calc_packet_size(const unsigned int num_fwdmsgs,
				  const unsigned int payload_size);

void ectp_build_packet(const unsigned int skipcount,
		      const struct ether_addr *fwdaddrs,
		      const unsigned int num_fwdaddrs,
		      const uint16_t rcpt_num,
		      const uint8_t *data,
		      const unsigned int data_size,
		      uint8_t packet_buf[],
		      const unsigned int packet_buf_size,
		      const uint8_t filler);

#endif /* __libectp_h__ */
