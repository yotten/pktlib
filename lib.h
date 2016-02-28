#ifndef _PKTLIB_LIB_H_INCLUDED_
#define _PKTLIB_LIB_H_INCLUDED_

struct _pktif_base { /* インターフェースの共通領域 */
	struct _pktif_base *next;
	int fd;
	unsigned long flags;
	int buffer_size;
	void *option; /* オプション領域 */
};

typedef struct _pktif_base *pktif_base_t;

void pktlib_error_exit(char *message);
int pktlib_iflist_set(pktif_t pktif);

#endif
