#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#ifdef __linux__
#include <netinet/ether.h>
#endif
#include <arpa/inet.h>

#include <netinet/ip_icmp.h>

#include "pingrep.h"
#include "lib.h"

static int make_srcmacaddr(char *macaddr, struct in_addr *ipaddr)
{
  macaddr[0] = 0x00;
  macaddr[1] = 0x11;
  memcpy(&macaddr[2], &ipaddr->s_addr, sizeof(in_addr_t));
  return 0;
}

static int memswap(void *p0, void *p1, int size)
{
  char *c0 = p0, *c1 = p1;
  char c;
  while (size > 0) {
    c = *c0; *c0 = *c1; *c1 = c;
    c0++; c1++; size--;
  }
  return 0;
}

static int pingrep_arp(char *buffer, int size, struct ether_header *ehdr)
{
  struct arphdr arphdr;
  char *p, *smac, *tmac, *sip, *tip;
  struct arpdata {
    union {
      char *octet;
      struct ether_addr *addr;
    } sender_macaddr;
    union {
      char *octet;
      struct ether_addr *addr;
    } target_macaddr;
    struct in_addr sender_ipaddr;
    struct in_addr target_ipaddr;
  } arpdata;

  if (size < sizeof(arphdr))
    return -1;
  memcpy(&arphdr, buffer, sizeof(arphdr));

  if ((ntohs(arphdr.ar_hrd) != ARPHRD_ETHER) ||
      (ntohs(arphdr.ar_pro) != ETHERTYPE_IP) ||
      (arphdr.ar_hln != ETHER_ADDR_LEN) ||
      (arphdr.ar_pln != sizeof(in_addr_t)))
    return -1;

  if (size < sizeof(struct arphdr) + arphdr.ar_hln * 2 + arphdr.ar_pln * 2)
    return -1;

  if (ntohs(arphdr.ar_op) != ARPOP_REQUEST)
    return -1;

  p = buffer + sizeof(struct arphdr);
  smac = p; p += arphdr.ar_hln;
  sip  = p; p += arphdr.ar_pln;
  tmac = p; p += arphdr.ar_hln;
  tip  = p; p += arphdr.ar_pln;

  arpdata.sender_macaddr.octet = smac;
  arpdata.target_macaddr.octet = tmac;
  memcpy(&arpdata.sender_ipaddr.s_addr, sip, sizeof(in_addr_t));
  memcpy(&arpdata.target_ipaddr.s_addr, tip, sizeof(in_addr_t));

  memswap(&arpdata.sender_ipaddr.s_addr,
	  &arpdata.target_ipaddr.s_addr, sizeof(in_addr_t));
  memcpy(arpdata.target_macaddr.octet, arpdata.sender_macaddr.octet,
	 ETHER_ADDR_LEN);
  make_srcmacaddr(arpdata.sender_macaddr.octet, &arpdata.sender_ipaddr);

  memcpy(ehdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(ehdr->ether_shost, arpdata.sender_macaddr.octet, ETHER_ADDR_LEN);

  arphdr.ar_op = htons(ARPOP_REPLY);

  memcpy(sip, &arpdata.sender_ipaddr.s_addr, sizeof(in_addr_t));
  memcpy(tip, &arpdata.target_ipaddr.s_addr, sizeof(in_addr_t));

  memcpy(buffer, &arphdr, sizeof(arphdr));

  size = p - buffer;

  return size;
}

static int pingrep_icmp(char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct icmp *icmphdr;

  if (size < sizeof(*icmphdr))
    return -1;
  icmphdr = (struct icmp *)buffer;

  if (icmphdr->icmp_type != ICMP_ECHO)
    return -1;

  icmphdr->icmp_type = ICMP_ECHOREPLY;

  /* This is compatible with FreeBSD */
  icmphdr->icmp_cksum = 0;
  icmphdr->icmp_cksum = htons(~ip_checksum(icmphdr, total_size));

  s = sizeof(*icmphdr);
  p += s;
  r += s;

  s = minval(total_size, size) - r;
  if (s > 0) {
    /* If need, attach payload here. */

    p += s;
    r += s;
  }

  return r;
}

static int pingrep_ip(char *buffer, int size, struct ether_header *ehdr)
{
  static char *pktbuf = NULL;
  static int bufsize = 0;
  char *p;
  int s, r = -1;
  struct ip *iphdr;
  int hdrsize, paysize;

  pktbuf = pkt_alloc_buffer(pktbuf, &bufsize, size);

  if (size < sizeof(*iphdr))
    return -1;

  memcpy(pktbuf, buffer, size);
  iphdr = (struct ip *)pktbuf;

  hdrsize = iphdr->ip_hl << 2;
  paysize = ntohs(iphdr->ip_len) - hdrsize;

  p = pktbuf + hdrsize;
  s = size   - hdrsize;

  if ((ntohs(iphdr->ip_off) & (IP_MF|IP_OFFMASK)) == 0) {
    switch (iphdr->ip_p) {
    case IPPROTO_ICMP: r = pingrep_icmp(p, s, paysize); break;
    default: break;
    }
  }

  if (r < 0)
    return r;

  if (size < hdrsize)
    return -1;

  iphdr->ip_ttl = 255;
  memswap(&iphdr->ip_src, &iphdr->ip_dst, sizeof(in_addr_t));

  /* This is compatible with FreeBSD */
  iphdr->ip_sum = 0;
  iphdr->ip_sum = htons(~ip_checksum(iphdr, hdrsize));

  memcpy(ehdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
  make_srcmacaddr((char *)ehdr->ether_shost, &iphdr->ip_src);

  p += r;
  r = p - pktbuf;

  s = minval(hdrsize + paysize, size) - r;
  if (s > 0) {
    /* If need, attach payload here. */

    p += s;
    r += s;
  }

  memcpy(buffer, pktbuf, r);

  return r;
}

int pkt_pingrep_ethernet(char *buffer, int size)
{
  char *p;
  int s, r = -1;
  struct ether_header ehdr;
  struct {
    pkt_uint16 tag;
    pkt_uint16 proto;
  } vlantag;
  int type;

  if (size < ETHER_HDR_LEN)
    return -1;
  memcpy(&ehdr, buffer, ETHER_HDR_LEN);

  type = ntohs(ehdr.ether_type);
  p = buffer + ETHER_HDR_LEN;
  s = size   - ETHER_HDR_LEN;

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100
#endif

  while (type == ETHERTYPE_VLAN) {
    if (s < sizeof(vlantag))
      return -1;
    memcpy(&vlantag, p, sizeof(vlantag));
    type = ntohs(vlantag.proto);
    p += sizeof(vlantag);
    s -= sizeof(vlantag);
  }

  ehdr.ether_type = htons(type);

  switch (type) {
  case ETHERTYPE_ARP: r = pingrep_arp(p, s, &ehdr); break;
  case ETHERTYPE_IP:  r = pingrep_ip( p, s, &ehdr); break;
  default: break;
  }

  if (r < 0)
    return r;

  if (p > buffer + ETHER_HDR_LEN) {
    memcpy(&vlantag, p - sizeof(vlantag), sizeof(vlantag));
    vlantag.proto = ehdr.ether_type;
    memcpy(p - sizeof(vlantag), &vlantag, sizeof(vlantag));
    ehdr.ether_type = htons(ETHERTYPE_VLAN);
  }

  memcpy(buffer, &ehdr, ETHER_HDR_LEN);

  p += r;
  r = p - buffer;

  s = size - r;
  if (s > 0) {
    /* If need, attach payload here. */

    p += s;
    r += s;
  }

  return r;
}
