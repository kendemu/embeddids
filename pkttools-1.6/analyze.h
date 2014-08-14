#ifndef _PKTTOOLS_ANALYZE_H_INCLUDED_
#define _PKTTOOLS_ANALYZE_H_INCLUDED_

struct timeval;
int pkt_analyze_ethernet(FILE *fp, char *buffer, int size, struct timeval *tm);

#endif
