#ifndef _NET_INET_ECTP_H_
#define _NET_INET_ECTP_H_

/*
 *	ectp.h
 *
 *	Ethernet Configuration Testing Protocol (ECTP) defines and structures
 *
 */

#include <linux/types.h>
#include <linux/if_ether.h>


/*
 * ECTP loopback assistance multicast address 
 */
#define ECTP_LA_MCADDR { 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00 }


/*
 * ECTP protocol header sizes in octets
 */
#define ECTP_DGRAM_HDR_SZ	2	/*
					 * ECTP header size in octets
					 * (i.e. skipcount field)
					*/

#define ECTP_FWDMSG_SZ		8	/*
					 * Forward Message size in octets.
					 * (includes Function field)
					 */


#define ECTP_REPLYMSG_MINSZ	4	/*
					 * Minimum Reply Message size in
					 * octets. (includes Function field)
					 */

#define ECTP_DGRAM_MIN_SZ	14	/*
					 * Must be the sum of the above :-)
					 */


/*
 * Function Code field values
 */

#define ECTP_RPLYMSG		1	/*
					 * Function Code field value for a
					 * ECTP Reply Message
					 */


#define ECTP_FWDMSG		2	/*
					 * Function Code field value for a
					 * ECTP Forward Message
					 */


/*
 * ECTP datagram structures
 */


/*
 * ECTP common header - only consists of the single 2 octet skip count
 * field.
 *
 * note: skipcount is little endian, i.e. _not_ traditional big endian
 * network order - don't use traditional ntohs() or htons() functions
 * on it, because they won't work.
 */
struct ectp_datagram_header {
        uint16_t skipcount; 
} __attribute__ ((packed));


/*
 * ECTP datagram
 */
struct ectp_datagram {
        struct ectp_datagram_header hdr;
        uint8_t payload[];
} __attribute__ ((packed));


/*
 * ECTP Reply Message (minus Function Code field)
 */
struct ectp_reply_message {
        uint16_t receiptnum;
        uint8_t data[];
} __attribute__ ((packed));


/*
 * ECTP Forward Message (minus Function Code field)
 */
struct ectp_forward_message {
        uint8_t fwdaddr[ETH_ALEN];
} __attribute__ ((packed));


/*
 * ECTP Message
 */
struct ectp_message {
        uint16_t func_code;
        union {
                struct ectp_forward_message fwd_msg;
                struct ectp_reply_message rply_msg;
        };
} __attribute__ ((packed));


#endif /* _NET_INET_ECTP_H_ */
