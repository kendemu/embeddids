#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

#include "bpf.h"
#include "rawsock.h"
#include "lib.h"

struct pkt_handler pkthandler = {
#ifdef __FreeBSD__
  bpf_open_recv, bpf_open_send, bpf_recv, bpf_send,
#endif
#ifdef __linux__
  rawsock_open_recv, rawsock_open_send, rawsock_recv, rawsock_send,
#endif
};

int minval(int v0, int v1)
{
  return (v0 < v1) ? v0 : v1;
}

int maxval(int v0, int v1)
{
  return (v0 > v1) ? v0 : v1;
}

int ip_checksum(void *buffer, int size)
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
    sum += ntohs(w.s);
    size -= 2;
  }
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);

  return sum;
}

void *pkt_alloc_buffer(void *buffer, int *sizep, int size)
{
  if ((buffer == NULL) || (*sizep < size)) {
    if (buffer)
      free(buffer);
    buffer = malloc(size);
    if (buffer == NULL)
      error_exit("Out of memory.\n");
    *sizep = size;
  }
  return buffer;
}

void error_exit(char *message)
{
  fprintf(stderr, message);
  exit(1);
}
