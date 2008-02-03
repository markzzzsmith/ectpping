
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include <net/ethernet.h>

#include "libenetaddr.h"


#define ENET_PADDR_LEN 17

static int ishex(unsigned char i);
static int isseperator(unsigned char i);
static int hexchar2bin(int i);


static int isseperator(unsigned char i)
{


	if ( (i == ':') || (i == '-') ) {
		return 1;
	} else {
		return 0;
	}

}


static int ishex(unsigned char i)
{


	if ( (i >= '0' && i <= '9') || (i >= 'a' && i <= 'f')
		|| (i >= 'A' && i <= 'F') ) {
		return 1;
	} else {
		return 0;
	}

}

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


enum enet_pton_ok enet_pton(const char *enet_paddr,
	uint8_t enet_addr[ETH_ALEN])
{
	int i,j;
	char tmpenet_paddr[ENET_PADDR_LEN+1];


	memcpy(tmpenet_paddr, enet_paddr, ENET_PADDR_LEN);	
	tmpenet_paddr[ENET_PADDR_LEN] = 0;

	if (strlen(tmpenet_paddr) != ENET_PADDR_LEN) { 
		return ENET_PTON_BADLENGTH;
	}

	for (i = 0; i < ENET_PADDR_LEN; i++) {

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
	for (i = 0; i < ENET_PADDR_LEN; i++) {

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
