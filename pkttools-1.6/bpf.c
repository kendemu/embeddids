#ifdef __FreeBSD__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/bpf.h>

#include "bpf.h"
#include "lib.h"

static unsigned long recv_flags = 0;
static unsigned long send_flags = 0;

static int bufsize;

static int open_free_bpf(int flags)
{
  int fd, i;
  char devfile[16];

#define BPF_DEVFILE "/dev/bpf"
  fd = open(BPF_DEVFILE, flags);
  if (fd < 0) {
    for (i = 0; i < 16; i++) {
      sprintf(devfile, "%s%d", BPF_DEVFILE, i);
      fd = open(devfile, flags);
      if (fd >= 0)
	break;
    }
  }
  if (fd < 0)
    error_exit("Cannot open bpf.\n");

  return fd;
}

int bpf_open_recv(char *ifname, unsigned long flags, int *bufsizep)
{
  int fd;
  struct ifreq ifr;
  unsigned int one = 1;
  unsigned int val;

  recv_flags = flags;

  fd = open_free_bpf(O_RDONLY);
  if (fd < 0)
    error_exit("Cannot open bpf.\n");

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  if (ioctl(fd, BIOCSETIF, &ifr) < 0)
    error_exit("Fail to ioctl BIOCSETIF.\n");
  if (ioctl(fd, BIOCGBLEN, &val) < 0)
    error_exit("Fail to ioctl BIOCIMMEDIATE.\n");
  bufsize = val;
  if (flags & PKT_RECV_FLAG_PROMISC) {
    if (ioctl(fd, BIOCPROMISC, NULL) < 0)
      error_exit("Fail to ioctl BIOCPROMISC.\n");
  }
  if (ioctl(fd, BIOCIMMEDIATE, &one) < 0)
    error_exit("Fail to ioctl BIOCIMMEDIATE.\n");
  val = (flags & PKT_RECV_FLAG_RECVONLY) ? 0 : 1;
  if (ioctl(fd, BIOCSSEESENT, &val) < 0)
    error_exit("Fail to ioctl BIOCSSEESENT.\n");
  if (ioctl(fd, BIOCFLUSH, NULL) < 0)
    error_exit("Fail to ioctl BIOCFLUSH.\n");

  if (bufsizep) *bufsizep = bufsize;

  return fd;
}

int bpf_open_send(char *ifname, unsigned long flags)
{
  int fd;
  struct ifreq ifr;
  unsigned int val;

  send_flags = flags;

  fd = open_free_bpf(O_RDWR);
  if (fd < 0)
    error_exit("Cannot open bpf.\n");

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  if (ioctl(fd, BIOCSETIF, &ifr) < 0)
    error_exit("Fail to ioctl BIOCSETIF.\n");
  val = (flags & PKT_SEND_FLAG_COMPLETE) ? 0 : 1;
  if (ioctl(fd, BIOCSHDRCMPLT, &val) < 0)
    error_exit("Fail to ioctl BIOCSHDRCMPLT.\n");

  return fd;
}

int bpf_recv(int fd, char *recvbuf, int recvsize, struct timeval *tm)
{
  int r;
  static int size;
  static char *buffer = NULL;
  static struct bpf_hdr *hdr = NULL;

  if (buffer == NULL) {
    buffer = malloc(bufsize);
    if (buffer == NULL)
      error_exit("Out of memory.\n");
  }

  while (hdr == NULL) {
    size = read(fd, buffer, bufsize);
    if (size > 0)
      hdr = (struct bpf_hdr *)buffer;
  }

  if (tm) {
    tm->tv_sec  = hdr->bh_tstamp.tv_sec;
    tm->tv_usec = hdr->bh_tstamp.tv_usec;
  }
  r = hdr->bh_caplen;
  if (r > recvsize) r = recvsize;
  memcpy(recvbuf, (char *)hdr + hdr->bh_hdrlen, r);

  hdr = (struct bpf_hdr *)
    ((char *)hdr + BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen));

  if ((char *)hdr >= buffer + size)
    hdr = NULL;

  return r;
}

int bpf_send(int fd, char *sendbuf, int sendsize)
{
  return write(fd, sendbuf, sendsize);
}
#endif
