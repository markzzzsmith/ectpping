
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <endian.h>
#include <byteswap.h>
#include <net/ethernet.h>

#include "libectp.h"

/*
 * ECTP packet utility functions
 */

/*
 * ectp_htons()
 *
 * ECTP host order to network order
 */
uint16_t ectp_htons(uint16_t i)
{


#if __BYTE_ORDER == __BIG_ENDIAN
	return (uint16_t) bswap_16(i);
#else
	return i;
#endif

}


/*
 * ectp_ntohs()
 *
 * ECTP network order to host order
 */
uint16_t ectp_ntohs(uint16_t i)
{


#if __BYTE_ORDER == __BIG_ENDIAN
	return (uint16_t) bswap_16(i);
#else
	return i;
#endif

}


/*
 * ectp_get_skipcount()
 *
 * Get the skipcount value from a ectp packet, and return it in host order
 */
unsigned int ectp_get_skipcount(const struct ectp_packet *ectp_pkt)
{


	return (unsigned int) ectp_ntohs(ectp_pkt->hdr.skipcount);

}


/*
 * ectp_set_skipcount()
 *
 * Set the skipcount value in an ectp packet, supplied in host order
 */
void ectp_set_skipcount(struct ectp_packet *ectp_pkt,
			const unsigned int skipcount)
{


	ectp_pkt->hdr.skipcount = ectp_htons((uint16_t)skipcount);

}


/*
 * ectp_skipc_basicchk_ok()
 *
 * Check if the skipcount value in the specified packet is ok to use.
 * note, ectp_pkt_len is assumed to be >= ECTP_REPLYMSG_MINSZ
 */
bool ectp_skipc_basicchk_ok(const unsigned int skipcount,
			    const unsigned int ectp_pkt_len)
{


	if ((skipcount & (ECTP_FWDMSG_SZ-1)) != 0)
		return false;

	if (skipcount >= ectp_pkt_len)
		return false;

	return true;

}


/*
 * ectp_get_msg_ptr()
 *
 * Returns a pointer to the message pointed to by the supplied skipcount
 * value.
 */
struct ectp_message *ectp_get_msg_ptr(const unsigned int skipcount,
				      const struct ectp_packet *ectp_pkt)
{

	return (struct ectp_message *)&(ectp_pkt->payload[skipcount]);

}


/*
 * ectp_get_curr_msg_ptr()
 *
 * Returns a pointer to the message pointed to by skipcount in the supplied
 * ECTP packet
 */
struct ectp_message *ectp_get_curr_msg_ptr(const struct ectp_packet
							*ectp_pkt)
{


	return ectp_get_msg_ptr(ectp_get_skipcount(ectp_pkt), ectp_pkt);

}


/*
 * ectp_get_msg_type()
 *
 * Returns the numeric message type value in host order for the supplied
 * message
 */
uint16_t ectp_get_msg_type(const struct ectp_message *ectp_msg)
{


	return ectp_ntohs(ectp_msg->hdr.func_code);

}


/*
 * ectp_set_msg_type()
 *
 * Set the message type in the provided ectp message
 */
void ectp_set_msg_type(struct ectp_message *ectp_msg,
		       const uint16_t msg_type)
{


	ectp_msg->hdr.func_code = ectp_htons(msg_type);

}


/*
 * ectp_fwdaddr_ok()
 *
 * checks if supplied forward message address is ok
 */
bool ectp_fwdaddr_ok(const uint8_t fwdaddr[ETH_ALEN])
{

	if (!(fwdaddr[0] & 0x01)) /* not bcast or mcast */
		return true;
	else
		return false;

}


/*
 * ectp_get_fwdaddr()
 *
 * Returns a pointer to the forwarding address in the supplied forward
 * message
 */
uint8_t *ectp_get_fwdaddr(const struct ectp_message *ectp_fwd_msg)
{


	return (uint8_t *) ectp_fwd_msg->fwd_msg.fwdaddr;

}

/*
 * ectp_set_fwdaddr()
 *
 * sets the forward address value in the specified forward message
 */
void ectp_set_fwdaddr(struct ectp_message *ectp_fwd_msg,
		      const uint8_t fwdaddr[ETH_ALEN])
{


	memcpy(ectp_fwd_msg->fwd_msg.fwdaddr, fwdaddr, ETH_ALEN);

}


/*
 * ectp_set_fwdmsg()
 *
 * setup a forward message
 */
void ectp_set_fwdmsg(struct ectp_message *ectp_fwd_msg,
		     const uint8_t fwdaddr[ETH_ALEN])
{


	ectp_set_msg_type(ectp_fwd_msg, ECTP_FWDMSG);

	ectp_set_fwdaddr(ectp_fwd_msg, fwdaddr);

}


/*
 * ectp_set_rplymsg_rcpt_num()
 *
 * sets the specified receipt number in the provided reply message
 */
void ectp_set_rplymsg_rcpt_num(struct ectp_message *ectp_rply_msg,
			       const uint16_t rcpt_num)
{


	ectp_rply_msg->rply_msg.rcpt_num = rcpt_num;

}


/*
 * ectp_get_rplymsg_rcpt_num()
 *
 * gets the specified receipt number form the provided reply message
 */
uint16_t ectp_get_rplymsg_rcpt_num(const struct ectp_message *ectp_rply_msg)
{


	return ectp_rply_msg->rply_msg.rcpt_num;

}


/*
 * ectp_set_rplymsg_hdr()
 *
 * Initialises a reply message header
 */
void ectp_set_rplymsg_hdr(struct ectp_message *ectp_rply_msg,
			  const uint16_t rcpt_num)
{


	ectp_set_msg_type(ectp_rply_msg, ECTP_RPLYMSG);

	ectp_set_rplymsg_rcpt_num(ectp_rply_msg, rcpt_num);

}


/*
 * ectp_set_rplymsg_data()
 *
 * Copies the supplied data into the reply message data field
 */
void ectp_set_rplymsg_data(struct ectp_message *ectp_rply_msg,
			   const uint8_t *data,
			   const unsigned int data_size)
{


	memcpy(ectp_rply_msg->rply_msg.data, data, data_size);

}


/*
 * Returns a pointer to the supplied reply message's data
 */
uint8_t *ectp_get_rplymsg_data_ptr(struct ectp_message *ectp_rply_msg)
{


	return ectp_rply_msg->rply_msg.data;

}


/*
 * ectp_inc_skipcount()
 *
 * Makes skipcount point to the next ECTP message in the supplied packet
 */
void ectp_inc_skipcount(struct ectp_packet *ectp_pkt)
{
	unsigned int skipcount;


	skipcount = ectp_get_skipcount(ectp_pkt);

	skipcount += ECTP_FWDMSG_SZ;

	ectp_set_skipcount(ectp_pkt, skipcount);

}


/*
 * ectp_calc_packet_size()
 *
 * Calculates the size the ECTP packet would be (not including ethernet header)
 */
unsigned int ectp_calc_packet_size(const unsigned int num_fwdmsgs,       
				  const unsigned int payload_size)
{


	return ECTP_PACKET_HDR_SZ + (num_fwdmsgs * ECTP_FWDMSG_SZ) +
		ECTP_REPLYMSG_MINSZ + payload_size;

}


/*
 * ectp_build_packet()
 *
 * Builds an ECTP packet, not including ethernet header
 */
void ectp_build_packet(const unsigned int skipcount,
		      const struct ether_addr *fwdaddrs,
		      const unsigned int num_fwdaddrs,
		      const uint16_t rcpt_num,
		      const uint8_t *data,
		      const unsigned int data_size,
		      uint8_t packet_buf[],
		      const unsigned int packet_buf_size,
		      const uint8_t filler)
{
	unsigned int packet_idx = 0;
	uint8_t tmp_buf[ECTP_FWDMSG_SZ];
	unsigned int buf_bytes_left = packet_buf_size;
	unsigned int i;
	const struct ether_addr *fwdaddr; /*
					   * obscure C const pointer thing,
					   * doesn't mean pointer value can't
					   * be modified, cause we do, just
					   * what it points to can't be.
					   */


	if (packet_buf_size == 0)
		goto out;

	memset(packet_buf, filler, packet_buf_size);

	/* ECTP packet header i.e. skipcount field */
	if (buf_bytes_left > ECTP_PACKET_HDR_SZ) {
		ectp_set_skipcount((struct ectp_packet *)&packet_buf[packet_idx],
			skipcount);
		packet_idx += ECTP_PACKET_HDR_SZ;
		buf_bytes_left -= ECTP_PACKET_HDR_SZ;
	} else {
		ectp_set_skipcount((struct ectp_packet *)tmp_buf,
			skipcount);
		memcpy(packet_buf, tmp_buf, packet_buf_size);
		goto out;
	}

	/* ECTP forward message(s) */
	fwdaddr = fwdaddrs;
	i = 1;
	while ((i <= num_fwdaddrs) && buf_bytes_left) {
		if (buf_bytes_left >= ECTP_FWDMSG_SZ) {
			ectp_set_fwdmsg((struct ectp_message *)
				&packet_buf[packet_idx], (uint8_t *)fwdaddr);
			fwdaddr++;
			packet_idx += ECTP_FWDMSG_SZ;
			buf_bytes_left -= ECTP_FWDMSG_SZ;
			i++;
		} else {
			ectp_set_fwdmsg((struct ectp_message *)tmp_buf,
				(uint8_t *)fwdaddr);
			memcpy(&packet_buf[packet_idx], tmp_buf, buf_bytes_left);
			buf_bytes_left = 0;
		}
	}

	if (!buf_bytes_left)
		goto out;

	/* ECTP reply message header */
	if (buf_bytes_left > ECTP_REPLYMSG_MINSZ) {
		ectp_set_rplymsg_hdr((struct ectp_message *)
			&packet_buf[packet_idx], rcpt_num);
		buf_bytes_left -= ECTP_REPLYMSG_MINSZ;
	} else {
		ectp_set_rplymsg_hdr((struct ectp_message *)tmp_buf,
			rcpt_num);
		memcpy(&packet_buf[packet_idx], tmp_buf, buf_bytes_left);
		goto out;
	}

	/* ECTP reply message data/payload */
	if (buf_bytes_left >= data_size) {
		ectp_set_rplymsg_data(
			(struct ectp_message *)&packet_buf[packet_idx],
			data, data_size);
	}  else {
		if (buf_bytes_left > 0)
			ectp_set_rplymsg_data(
				(struct ectp_message *)&packet_buf[packet_idx],
				data, buf_bytes_left);
	}

out:
	return;

}

/* EOF */
