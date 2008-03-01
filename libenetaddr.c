
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#include <net/ethernet.h>

#include "libenetaddr.h"


static int ishex(unsigned char i);
static int isseperator(unsigned char i);
static int hexchar2bin(int i);


/*
 * Is the supplied character an ethernet MAC address
 * seperator?
 */
static int isseperator(unsigned char i)
{


	if ( (i == ':') || (i == '-') ) {
		return 1;
	} else {
		return 0;
	}

}


/*
 * Does supplied character fall within hexadecimal
 * character range?
 */
static int ishex(unsigned char i)
{


	if ( (i >= '0' && i <= '9') || (i >= 'a' && i <= 'f')
		|| (i >= 'A' && i <= 'F') ) {
		return 1;
	} else {
		return 0;
	}

}


/*
 * Convert hexidecimal character to binary value equivalent
 */
static int hexchar2bin(int i)
{


	if ( (i >= '0') && (i <= '9') ) {
		return (i - '0');
	}

	if ( ((i >= 'a') && (i <= 'f')) || ((i >= 'A') && (i <= 'F')) ) {
		return ((tolower(i) - 'a') + 10);
		
	}

	return i;

}


/*
 * Ethernet address Presentation to Network function
 */
enum enet_pton_ok enet_pton(
				const char *enet_paddr,
				uint8_t enet_addr[ETH_ALEN])
{
	int i,j;
	char tmpenet_paddr[ENET_PADDR_MAXSZ];


	memcpy(tmpenet_paddr, enet_paddr, ENET_PADDR_MAXSZ);	
	tmpenet_paddr[ENET_PADDR_MAXSZ-1] = 0;

	if (strlen(tmpenet_paddr) != (ENET_PADDR_MAXSZ-1)) 
		return ENET_PTON_BADLENGTH;

	for (i = 0; i < (ENET_PADDR_MAXSZ-1); i++) {

		if ( (i % 3) != 2 ) { /* seperator every 3 chars */
			if (ishex(tmpenet_paddr[i]) != 1 ) {
				return ENET_PTON_BADHEX;
			}
		} else {
			if (isseperator(tmpenet_paddr[i]) != 1) {
				return ENET_PTON_BADSEPERATOR;
			}
		}
		
	}

	/*
	 * MAC address string should be a good one at this point. Next trick
	 * is to convert it from ascii to binary, and stick it the supplied
	 * MAC address array.
	 */

	j = 0;
	for (i = 0; i < (ENET_PADDR_MAXSZ-1); i++) {

		if ( (i % 3) != 2) { /* skip seperator chars */

			if ( (j & 1) == 0) { 
				/*
				 * j is even, meaning that the value we're
				 * going to convert to is the high order
				 * four bits of the MAC address octet
				 */
				enet_addr[j / 2] =
					hexchar2bin(tmpenet_paddr[i]) << 4;
			} else {
				enet_addr[j / 2] = enet_addr[j / 2] +
					hexchar2bin(tmpenet_paddr[i]);
			}

			j++;

		}
	}

	return ENET_PTON_GOOD;

}


/*
 * Ethernet address Network to Presentation function
 */
enum enet_ntop_ok enet_ntop(
				const uint8_t enet_addr[ETH_ALEN],
				const enum enet_ntop_format enet_ntop_fmt,
				char *buf, const unsigned int buf_size)
{


	switch (enet_ntop_fmt) {
	case ENET_NTOP_UNIX:
		if (buf_size < 18)
			return ENET_NTOP_BADBUFLEN;
		snprintf(buf, buf_size, "%02x:%02x:%02x:%02x:%02x:%02x",
			enet_addr[0],
			enet_addr[1],
			enet_addr[2],
			enet_addr[3],
			enet_addr[4],
			enet_addr[5]);
		break;
	case ENET_NTOP_SUNUNIX:
		if (buf_size < 18)
			return ENET_NTOP_BADBUFLEN;
		snprintf(buf, buf_size, "%x:%x:%x:%x:%x:%x",
			enet_addr[0],
			enet_addr[1],
			enet_addr[2],
			enet_addr[3],
			enet_addr[4],
			enet_addr[5]);
		break;
	case ENET_NTOP_CISCO:
		if (buf_size < 15)
			return ENET_NTOP_BADBUFLEN;
		snprintf(buf, buf_size, "%02x%02x.%02x%02x.%02x%02x",
			enet_addr[0],
			enet_addr[1],
			enet_addr[2],
			enet_addr[3],
			enet_addr[4],
			enet_addr[5]);
		break;
	case ENET_NTOP_802CANONLC:
		if (buf_size < 18)
			return ENET_NTOP_BADBUFLEN;
		snprintf(buf, buf_size, "%02x-%02x-%02x-%02x-%02x-%02x",
			enet_addr[0],
			enet_addr[1],
			enet_addr[2],
			enet_addr[3],
			enet_addr[4],
			enet_addr[5]);
		break;
	case ENET_NTOP_PACKED:
		if (buf_size < 12)
			return ENET_NTOP_BADBUFLEN;
		snprintf(buf, buf_size, "%02X%02X%02X%02X%02X%02X",
			enet_addr[0],
			enet_addr[1],
			enet_addr[2],
			enet_addr[3],
			enet_addr[4],
			enet_addr[5]);
		break;
	case ENET_NTOP_PACKEDLC:
		if (buf_size < 12)
			return ENET_NTOP_BADBUFLEN;
		snprintf(buf, buf_size, "%02x%02x%02x%02x%02x%02x",
			enet_addr[0],
			enet_addr[1],
			enet_addr[2],
			enet_addr[3],
			enet_addr[4],
			enet_addr[5]);
		break;
	case ENET_NTOP_802CANON:
	default:
		if (buf_size < 18)
			return ENET_NTOP_BADBUFLEN;
		snprintf(buf, buf_size, "%02X-%02X-%02X-%02X-%02X-%02X",
			enet_addr[0],
			enet_addr[1],
			enet_addr[2],
			enet_addr[3],
			enet_addr[4],
			enet_addr[5]);
		break;
	}

	return ENET_NTOP_GOOD;

}
