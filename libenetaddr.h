#ifndef _ENETADDR_H_
#define _ENETADDR_H_

#include <stdint.h>

#include <net/ethernet.h>

enum enet_pton_ok {
	ENET_PTON_GOOD,
	ENET_PTON_BADLENGTH,
	ENET_PTON_BADHEX,
	ENET_PTON_BADSEPERATOR
};

enum enet_pton_ok enet_pton(const char *enet_paddr,
	uint8_t enet_addr[ETH_ALEN]);


enum enet_ntop_format {
	ENET_NTOP_802CANON,	/* IEEE 802 Canonical Address format */
	ENET_NTOP_802CANONLC,	/* Lower case 802 Canonical */
	ENET_NTOP_UNIX,		/* Traditional Unix format */
	ENET_NTOP_SUNUNIX,	/* Traditional Unix minus leading zeros */
	ENET_NTOP_CISCO,	/* Cisco address format */
	ENET_NTOP_PACKED,	/* Upper case, minus seperators */
	ENET_NTOP_PACKEDLC	/* Lower case, minus seperators */
};

enum enet_ntop_ok {
	ENET_NTOP_GOOD,
	ENET_NTOP_BADBUFLEN
};

enum enet_ntop_ok enet_ntop(const uint8_t enet_addr[ETH_ALEN],
	const enum enet_ntop_format enet_ntop_fmt,
	char *buf, const unsigned int buf_size);

#endif /* _ENETADDR_H_ */
