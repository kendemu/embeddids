#ifdef __FreeBSD__
#ifndef _PKTTOOLS_BPF_H_INCLUDED_
#define _PKTTOOLS_BPF_H_INCLUDED_

struct timeval;
int bpf_open_recv(char *ifname, unsigned long flags, int *bufsizep);
int bpf_open_send(char *ifname, unsigned long flags);
int bpf_recv(int fd, char *recvbuf, int recvsize, struct timeval *tm);
int bpf_send(int fd, char *sendbuf, int sendsize);

#endif
#endif
