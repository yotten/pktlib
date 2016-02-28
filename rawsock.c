#ifdef __linux__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netpacket/packet.h>

#include "pktlib.h"
#include "lib.h"

struct _pktif {
	struct _pktif_base base; /* 共通領域は先頭に置く必要がある */
	struct { /* インターフェースのRAWソケット共通部分 */
		int ifindex;
	} rawsock;
};

pktif_t pktif_open(char *ifname, unsigned long flags, int option_size)
{
	pktif_t pktif;
	int s, ifindex, buffer_size;
	struct ifreq ifr;
	struct sockaddr_ll sll;
	struct packet_mreq mreq;
	int optval;
	socklen_t optlen;

	pktif = malloc(sizeof(*pktif) + option_size);
	memset(pktif, 0, sizeof(*pktif) + option_size);

	s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); /* RAWソケットを開く */
	if (s < 0)
		pktlib_error_exit("Cannot open raw socket.\n");

	/* 情報の取得 */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) /* インターフェース番号を取得 */
	pktlib_error_exit("Fail to ioctl SIOCGIFINDEX.\n");
	ifindex = ifr.ifr_ifindex;
	optlen = sizeof(optval);
	if (getsockopt(s, SOL_SOCKET, SO_RCVBUF, &optval, &optlen) < 0)
		pktlib_error_exit("Fail to getsockopt SO_RCVBUF.\n");
	buffer_size = optval / 2; /* 受信バッファの必要サイズ */

	/* 受信関連の設定 */
	if (!(flags & PKTIF_OPEN_FLAG_RECV_NOTPROM)) {
		memset(&mreq, 0, sizeof(mreq));
		mreq.mr_type = PACKET_MR_PROMISC; /* 自宛でないパケットも受信する */
		mreq.mr_ifindex = ifindex;
		if (setsockopt(s, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
			pktlib_error_exit("Fail to setsockopt PACKET_ADD_MEMBERSHIP.\n");
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = ifindex; /* インターフェースを設定する */
	if (bind(s, (struct sockaddr *)&sll, sizeof(sll)) < 0)
		pktlib_error_exit("Cannot bind.\n");

	pktif->base.next = NULL;
	pktif->base.fd = s;
	pktif->base.flags = flags;
	pktif->base.buffer_size = buffer_size;
	pktif->base.option = (option_size > 0) ? (pktif + 1) : NULL;
	pktif->rawsock.ifindex = ifindex;

	pktlib_iflist_set(pktif); /* select()のためにリンクリストに接続する */

	return pktif;
}

int pktif_is_empty(pktif_t pktif)
{
  return 1; /* BPFとの整合性のための関数．常に１を返す */
}

int pktif_recv(pktif_t pktif, char *buffer, int size, struct timeval *tm)
{
	int r;
	socklen_t optlen;
	struct sockaddr_ll sll;

	while (1) {
		optlen = sizeof(sll);
		r = recvfrom(pktif->base.fd, buffer, size, 0,
		 (struct sockaddr *)&sll, &optlen); /* パケットの受信 */
		if (r <= 0)
			return r;
		if (!(pktif->base.flags & PKTIF_OPEN_FLAG_RECV_NOTSENT))
			break;
		if (sll.sll_pkttype != PACKET_OUTGOING) /* 自発のパケットは破棄する */
			break;
	}

	if (tm) { /* 受信時刻を取得 */
		if (ioctl(pktif->base.fd, SIOCGSTAMP, tm) < 0)
		pktlib_error_exit("Fail to ioctl SIOCGSTAMP.\n");
	}

	return r;
}

int pktif_send(pktif_t pktif, char *buffer, int size)
{
	return send(pktif->base.fd, buffer, size, 0); /* パケットの送信 */
}
#endif
