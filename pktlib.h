#ifndef _PKTLIB_PKTLIB_H_INCLUDED_
#define _PKTLIB_PKTLIB_H_INCLUDED_

typedef struct _pktif *pktif_t;

#define PKTIF_OPEN_FLAG_RECV_NOTPROM    (1<< 0)
#define PKTIF_OPEN_FLAG_RECV_NOTSENT    (1<< 1)
#define PKTIF_OPEN_FLAG_SELECT_DISABLE  (1<<16)
#define PKTIF_OPEN_FLAG_SELECT_NOSELECT (1<<17)

/* 送受信関連 */
pktif_t pktif_open(char *ifname, unsigned long flags, int option_size);
int pktif_is_empty(pktif_t pktif);
int pktif_recv(pktif_t pktif, char *buffer, int size, struct timeval *tm);
int pktif_send(pktif_t pktif, char *buffer, int size);

/* パラメータ取得 */
int pktif_get_fd(pktif_t pktif);
unsigned long pktif_get_flags(pktif_t pktif);
int pktif_get_buffer_size(pktif_t pktif);
void *pktif_get_option(pktif_t pktif);
pktif_t pktif_get_next(pktif_t pktif);

/* select()のためのリンクリスト関連 */
pktif_t pktlib_iflist_get_list();
pktif_t pktlib_iflist_select(int usec);

/* その他ライブラリ */
int pktlib_ip_checksum(void *buffer, int size);

#endif
