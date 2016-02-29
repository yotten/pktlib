#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "pktlib.h"
#include "lib.h"

static struct {
	pktif_base_t list;
	int fdnum;
	fd_set readfds; /* オープンしたインターフェースの一覧 */
	fd_set fds; /* select()によって返されたread()可能インターフェース一覧 */
} pktif_list; /* オープンしたインターフェースのリスト */

int pktif_get_fd(pktif_t pktif)
{
	return ((pktif_base_t)pktif)->fd;
}

unsigned long pktif_get_flags(pktif_t pktif)
{
	return ((pktif_base_t)pktif)->flags;
}

int pktif_get_buffer_size(pktif_t pktif)
{
	return ((pktif_base_t)pktif)->buffer_size;
}

void *pktif_get_option(pktif_t pktif)
{
	return ((pktif_base_t)pktif)->option;
}

pktif_t pktif_get_next(pktif_t pktif)
{
	return (pktif_t)((pktif_base_t)pktif)->next;
}

static void init()
{
	static int initialized = 0;
	if (!initialized) {
		pktif_list.list = NULL;
		pktif_list.fdnum = 0;
		FD_ZERO(&pktif_list.readfds);
		FD_ZERO(&pktif_list.fds);
		initialized = 1;
	}
}

pktif_t pktlib_iflist_get_list()
{
	init();
	return (pktif_t)pktif_list.list;
}

int pktlib_iflist_set(pktif_t pktif)
{
	pktif_base_t base = (pktif_base_t)pktif;

	init();

	if (base->flags & PKTIF_OPEN_FLAG_SELECT_DISABLE)
		return -1;

	base->next = pktif_list.list; /* リンクリストに接続する */
	pktif_list.list = base;

	if (base->flags & PKTIF_OPEN_FLAG_SELECT_NOSELECT)
		return 0;

	if (pktif_list.fdnum < base->fd + 1)
		pktif_list.fdnum = base->fd + 1;
	FD_SET(base->fd, &pktif_list.readfds); /* インターフェース一覧に追加 */
	return 1;
}

pktif_t pktlib_iflist_select(int usec)
{
	pktif_t pktif;
	pktif_base_t base;
	struct timeval t, *tp = NULL;

	init();

	/* 残っている受信パケットが無いか調べる */
	for (base = pktif_list.list; base; base = base->next) {
		if (base->flags & PKTIF_OPEN_FLAG_SELECT_NOSELECT)
			continue;
		pktif = (pktif_t)base;
		if (!pktif_is_empty(pktif)) /* 受信バッファに残っている */
			return pktif;
		if (FD_ISSET(base->fd, &pktif_list.fds)) { /* 以前の受信待ちがある */
			FD_CLR(base->fd, &pktif_list.fds);
			return pktif;
		}
	}

	if (usec >= 0) { /* タイムアウト時間を設定(負の値ならタイムアウトしない) */
		t.tv_sec  = usec / 1000000;
		t.tv_usec = usec % 1000000;
		tp = &t;
	}

	pktif_list.fds = pktif_list.readfds;
	pktif = NULL;
	if (select(pktif_list.fdnum, &pktif_list.fds, NULL, NULL, tp) > 0) {
		for (base = pktif_list.list; base; base = base->next) {
			if (FD_ISSET(base->fd, &pktif_list.fds)) { /* 受信待ちがある */
				pktif = (pktif_t)base;
				FD_CLR(base->fd, &pktif_list.fds);
				break;
			}
		}
	}

	return pktif;
}

void pktlib_error_exit(char *message)
{
	fprintf(stderr, message);
	exit(1);
}

int pktlib_ip_checksum(void *buffer, int size)
{
	union {
		char c[2];
		unsigned short s;
	} w;
	char *p;
	int sum = 0;

	for (p = buffer; size > 0; p += 2) {
		w.c[0] = p[0];
		w.c[1] = (size > 1) ? p[1] : 0;
		sum += w.s; /* IPチェックサム計算は両エンディアンでOKなのでntohs()は不要 */
		size -= 2;
	}
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);

	return sum;
}
