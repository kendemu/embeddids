#ifdef __linux__
#ifndef _PKTTOOLS_RAWSOCK_H_INCLUDED_
#define _PKTTOOLS_RAWSOCK_H_INCLUDED_

struct timeval;
int rawsock_open_recv(char *ifname, unsigned long flags, int *bufsizep);
int rawsock_open_send(char *ifname, unsigned long flags);
int rawsock_recv(int fd, char *recvbuf, int recvsize, struct timeval *tm);
int rawsock_send(int fd, char *sendbuf, int sendsize);

#endif
#endif
