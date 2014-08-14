#ifdef __linux__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netpacket/packet.h>

#include "rawsock.h"
#include "lib.h"

static unsigned long recv_flags = 0;
static unsigned long send_flags = 0;

static int ifindex;

static char macaddr_src[ETHER_ADDR_LEN];

static int flush_recv_buffer(int s, int size)
{
  fd_set fds;
  struct timeval timeout;
  char *buffer = NULL;
  int r;

  timeout.tv_sec = timeout.tv_usec = 0;

  while (size > 0) {
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    r = select(s + 1, &fds, NULL, NULL, &timeout);
    if (r < 0) continue;
    if ((r == 0) || ((r > 0) && !FD_ISSET(s, &fds)))
      break;
    if (buffer == NULL) {
      buffer = malloc(size);
      if (buffer == NULL)
	error_exit("Out of memory.\n");
    }
    r = recv(s, buffer, size, 0);
    if (r < 0)
      error_exit("Cannot flush buffer.\n");
    if (r == 0)
      break;
    size =- r;
  }

  if (buffer) free(buffer);

  return 0;
}

int rawsock_open_recv(char *ifname, unsigned long flags, int *bufsizep)
{
  int s, bufsize;
  struct ifreq ifr;
  struct sockaddr_ll sll;
  struct packet_mreq mreq;
  int optval;
  socklen_t optlen;

  recv_flags = flags;

  s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (s < 0)
    error_exit("Cannot open raw socket.\n");

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  if (ioctl(s, SIOCGIFINDEX, &ifr) < 0)
    error_exit("Fail to ioctl SIOCGIFINDEX.\n");
  ifindex = ifr.ifr_ifindex;

  optlen = sizeof(optval);
  if (getsockopt(s, SOL_SOCKET, SO_RCVBUF, &optval, &optlen) < 0)
    error_exit("Fail to getsockopt SO_RCVBUF.\n");
  bufsize = optval / 2;

  if (flags & PKT_RECV_FLAG_PROMISC) {
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_type = PACKET_MR_PROMISC;
    mreq.mr_ifindex = ifindex;
    if (setsockopt(s, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
		   &mreq, sizeof(mreq)) < 0)
      error_exit("Fail to setsockopt PACKET_ADD_MEMBERSHIP.\n");
  }

  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = ifindex;
  if (bind(s, (struct sockaddr *)&sll, sizeof(sll)) < 0)
    error_exit("Cannot bind.\n");

  flush_recv_buffer(s, bufsize);

  if (bufsizep) *bufsizep = bufsize;

  return s;
}

int rawsock_open_send(char *ifname, unsigned long flags)
{
  int s;
  struct ifreq ifr;
  struct sockaddr_ll sll;

  send_flags = flags;

  s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (s < 0)
    error_exit("Cannot open raw socket.\n");

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  if (ioctl(s, SIOCGIFINDEX, &ifr) < 0)
    error_exit("Fail to ioctl SIOCGIFINDEX.\n");
  ifindex = ifr.ifr_ifindex;

  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = ifindex;
  if (bind(s, (struct sockaddr *)&sll, sizeof(sll)) < 0)
    error_exit("Cannot bind.\n");

  if (flags & PKT_SEND_FLAG_COMPLETE) {
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
      error_exit("Fail to ioctl SIOCGIFHWADDR.\n");
    memcpy(macaddr_src, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
  }

  return s;
}

int rawsock_recv(int fd, char *recvbuf, int recvsize, struct timeval *tm)
{
  int size;
  socklen_t optlen;
  struct sockaddr_ll sll;
  struct timeval t;

  while (1) {
    optlen = sizeof(sll);
    size = recvfrom(fd, recvbuf, recvsize, 0,
		    (struct sockaddr *)&sll, &optlen);
    if (!(recv_flags & PKT_RECV_FLAG_RECVONLY))
      break;
    if (sll.sll_pkttype != PACKET_OUTGOING)
      break;
  }

  if (tm) {
    if (ioctl(fd, SIOCGSTAMP, &t) < 0)
      error_exit("Cannot get timestamp.\n");
    tm->tv_sec  = t.tv_sec;
    tm->tv_usec = t.tv_usec;
  }

  return size;
}

int rawsock_send(int fd, char *sendbuf, int sendsize)
{
  int r;
  struct sockaddr_ll sll;
  struct ether_header *ehdr;
  char macaddr_save[ETHER_ADDR_LEN];
  int complete = 0;

  ehdr = (struct ether_header *)sendbuf;

  if ((send_flags & PKT_SEND_FLAG_COMPLETE) && (sendsize >= ETHER_HDR_LEN)) {
    complete = 1;
  }
  if (complete) {
    memcpy(macaddr_save, ehdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(ehdr->ether_shost, macaddr_src, ETHER_ADDR_LEN);
  }

  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = ifindex;
  r = sendto(fd, sendbuf, sendsize, 0, (struct sockaddr *)&sll, sizeof(sll));

  if (complete) {
    memcpy(ehdr->ether_shost, macaddr_save, ETHER_ADDR_LEN);
  }

  return r;
}
#endif
