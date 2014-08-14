#ifndef _PKTTOOLS_LIB_H_INCLUDED_
#define _PKTTOOLS_LIB_H_INCLUDED_

#define PKT_BUFFER_SIZE_DEFAULT 0x14000 /* 80KB */

#define PKT_RECV_FLAG_PROMISC  (1<< 0)
#define PKT_RECV_FLAG_RECVONLY (1<< 1)
#define PKT_SEND_FLAG_COMPLETE (1<<16)
#define PKT_SEND_FLAG_INTERVAL (1<<17)

typedef long pkt_int32;
typedef unsigned long pkt_uint32;
typedef short pkt_int16;
typedef unsigned short pkt_uint16;
typedef char pkt_int8;
typedef unsigned char pkt_uint8;

struct timeval;

struct pkt_handler {
  int (*open_recv)(char *ifname, unsigned long flags, int *bufsizep);
  int (*open_send)(char *ifname, unsigned long flags);
  int (*recv)(int fd, char *recvbuf, int recvsize, struct timeval *tm);
  int (*send)(int fd, char *sendbuf, int sendsize);
};

extern struct pkt_handler pkthandler;

int minval(int v0, int v1);
int maxval(int v0, int v1);

int ip_checksum(void *buffer, int size);

void *pkt_alloc_buffer(void *buffer, int *sizep, int size);

void error_exit(char *message);

#endif
