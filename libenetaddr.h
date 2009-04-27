#ifndef _ENETADDR_H_
#define _ENETADDR_H_

/*
 * libenetaddr.h - ethernet address handling routines
 *
 * Copyright (C) 2008-2009, Mark Smith <markzzzsmith@yahoo.com.au>
 * All rights reserved.
 *
 * Licensed under the GNU General Public Licence (GPL) Version 2 only.
 * This explicitly does not include later versions, such as revisions of 2 or
 * Version 3, and later versions.
 * See the accompanying LICENSE file for full terms and conditions.
 *
 */


#include <stdint.h>

#include <net/ethernet.h>

#define ENET_PADDR_MAXSZ 18

enum enet_pton_ok {
	ENET_PTON_GOOD,
	ENET_PTON_BADLENGTH,
	ENET_PTON_BADHEX,
	ENET_PTON_BADSEPERATOR
};


/*
 * Convert supplied mac address in char format to binary. Only supports
 * xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx format char addresses
 */
enum enet_pton_ok enet_pton(const char *enet_paddr,
			    struct ether_addr *enet_addr);


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

enum enet_ntop_ok enet_ntop(const struct ether_addr *enet_addr,
			    const enum enet_ntop_format enet_ntop_fmt,
			    char *buf, const unsigned int buf_size);

#endif /* _ENETADDR_H_ */
