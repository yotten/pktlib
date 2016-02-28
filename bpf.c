#ifdef __FreeBSD__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/bpf.h>

#include "pktlib.h"
#include "lib.h"

struct _pktif {
  struct _pktif_base base; /* 共通領域は先頭に置く必要がある */
  struct { /* インターフェースのBPF依存部分 */
    char *buffer;
    int bufsize;
    int readsize;
    struct bpf_hdr *hdr;
  } bpf;
};

pktif_t pktif_open(char *ifname, unsigned long flags, int option_size)
{
  pktif_t pktif;
  int fd, buffer_size;
  struct ifreq ifr;
  unsigned int one = 1, val;

  pktif = malloc(sizeof(*pktif) + option_size);
  memset(pktif, 0, sizeof(*pktif) + option_size);

  fd = open("/dev/bpf", O_RDWR); /* BPFを開く */
  if (fd < 0)
    pktlib_error_exit("Cannot open bpf.\n");

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  if (ioctl(fd, BIOCSETIF, &ifr) < 0) /* インターフェースを設定する */
    pktlib_error_exit("Fail to ioctl BIOCSETIF.\n");

  /* 情報の取得 */
  if (ioctl(fd, BIOCGBLEN, &val) < 0) /* 受信バッファの必要サイズ */
    pktlib_error_exit("Fail to ioctl BIOCGBLEN.\n");
  buffer_size = val;

  /* 受信関連の設定 */
  if (!(flags & PKTIF_OPEN_FLAG_RECV_NOTPROM)) {
    if (ioctl(fd, BIOCPROMISC, NULL) < 0) /* 自宛でないパケットも受信する */
      pktlib_error_exit("Fail to ioctl BIOCPROMISC.\n");
  }
  if (ioctl(fd, BIOCIMMEDIATE, &one) < 0) /* 受信したら即時read()する */
    pktlib_error_exit("Fail to ioctl BIOCIMMEDIATE.\n");
  val = (flags & PKTIF_OPEN_FLAG_RECV_NOTSENT) ? 0 : 1;
  if (ioctl(fd, BIOCSSEESENT, &val) < 0) /* 出力パケットも受信する */
    pktlib_error_exit("Fail to ioctl BIOCSSEESENT.\n");
  if (ioctl(fd, BIOCFLUSH, NULL) < 0) /* 受信バッファをフラッシュする */
    pktlib_error_exit("Fail to ioctl BIOCFLUSH.\n");

  /* 送信関連の設定 */
  if (ioctl(fd, BIOCSHDRCMPLT, &one) < 0) /* MACアドレスを補間しない */
    pktlib_error_exit("Fail to ioctl BIOCSHDRCMPLT.\n");

  pktif->base.next = NULL;
  pktif->base.fd = fd;
  pktif->base.flags = flags;
  pktif->base.buffer_size = buffer_size;
  pktif->base.option = (option_size > 0) ? (pktif + 1) : NULL;
  pktif->bpf.buffer = malloc(buffer_size); /* 受信バッファを獲得 */
  pktif->bpf.bufsize = buffer_size;
  pktif->bpf.readsize = 0;

  pktlib_iflist_set(pktif); /* select()のためにリンクリストに接続する */

  return pktif;
}

int pktif_is_empty(pktif_t pktif)
{
  return (pktif->bpf.readsize == 0) ? 1 : 0;
}

int pktif_recv(pktif_t pktif, char *buffer, int size, struct timeval *tm)
{
  struct bpf_hdr *hdr;
  int r;

  /*
   * BPFではヘッダが付加され複数パケットが返されるので，以前にread()した
   * ときの受信パケットが受信バッファ上に残っている場合にはそれを返す．
   * 残っていないならばread()で新規に受信する．
   */

  if (pktif_is_empty(pktif)) { /* パケットの受信 */
    r = read(pktif->base.fd, pktif->bpf.buffer, pktif->bpf.bufsize);
    if (r <= 0)
      return r;
    pktif->bpf.readsize = r;
    pktif->bpf.hdr = (struct bpf_hdr *)pktif->bpf.buffer;
  }

  hdr = pktif->bpf.hdr;

  if (tm) {
    tm->tv_sec  = hdr->bh_tstamp.tv_sec;
    tm->tv_usec = hdr->bh_tstamp.tv_usec;
  }
  if (size > hdr->bh_caplen)
    size = hdr->bh_caplen;
  memcpy(buffer, (char *)hdr + hdr->bh_hdrlen, hdr->bh_caplen);

  pktif->bpf.hdr = (struct bpf_hdr *)
    ((char *)hdr + BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen));

  if ((char *)pktif->bpf.hdr >= pktif->bpf.buffer + pktif->bpf.readsize)
    pktif->bpf.readsize = 0;

  return size;
}

int pktif_send(pktif_t pktif, char *buffer, int size)
{
  return write(pktif->base.fd, buffer, size); /* パケットの送信 */
}
#endif
