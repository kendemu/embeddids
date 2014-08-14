#ifndef _PKTTOOLS_PCAP_H_INCLUDED_
#define _PKTTOOLS_PCAP_H_INCLUDED_

struct timeval;
int pkt_pcap_read(FILE *fp, char *p, int size,
		  int *capsizep, int *origsizep, struct timeval *tm);
int pkt_pcap_write(FILE *fp, char *p,
		   int capsize, int origsize, struct timeval *tm);

#endif
