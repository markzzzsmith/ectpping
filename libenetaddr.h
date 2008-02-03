
enum enet_pton_ok {
	ENET_PTON_GOOD,
	ENET_PTON_BADLENGTH,
	ENET_PTON_BADHEX,
	ENET_PTON_BADSEPERATOR
};


enum enet_pton_ok enet_pton(const char *enet_paddr,
	uint8_t enet_addr[ETH_ALEN]);
