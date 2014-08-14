#ifdef __linux__
#define _BSD_SOURCE
#endif
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
#include <netinet/igmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include "filter.h"
#include "lib.h"

#define REJECT 0
#define PASS   1

/* Select filter rule (choose PASS or REJECT) */
#define FILTER_RULE_MATCH   REJECT
#define FILTER_RULE_UNMATCH PASS

#define   MATCH(f) do { (f) |= 1; } while (0)
#define UNMATCH(f) do { /* nop */ } while (0)

static int filter_arp(int *f, char *buffer, int size)
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

  /*********************************/
  /* SETUP FILTER RULE AS YOU LIKE */
  /*********************************/

  switch (ntohs(arphdr.ar_op)) { /* operation */
  case ARPOP_REQUEST: UNMATCH(*f); break;
  case ARPOP_REPLY:   UNMATCH(*f); break;
  default:            UNMATCH(*f); break;
  }
  switch (ntohs(arphdr.ar_hrd)) { /* hardware */
  case ARPHRD_ETHER: UNMATCH(*f); break;
  default:           UNMATCH(*f); break;
  }
  switch (ntohs(arphdr.ar_pro)) { /* protocol */
  case ETHERTYPE_IP: UNMATCH(*f); break;
  default:           UNMATCH(*f); break;
  }
  switch (arphdr.ar_hln) { /* hard size */
  case ETHER_ADDR_LEN: UNMATCH(*f); break;
  default:             UNMATCH(*f); break;
  }
  switch (arphdr.ar_pln) { /* proto size */
  case sizeof(in_addr_t): UNMATCH(*f); break;
  default:                UNMATCH(*f); break;
  }

  if (size < sizeof(struct arphdr) + arphdr.ar_hln * 2 + arphdr.ar_pln * 2)
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

  /*********************************/
  /* SETUP FILTER RULE AS YOU LIKE */
  /*********************************/

  if (!memcmp(arpdata.sender_macaddr.octet, /* sender MAC */
	      "\xFF\xFF\xFF\xFF\xFF\xFF", ETHER_ADDR_LEN))
    UNMATCH(*f);
  if (!memcmp(arpdata.target_macaddr.octet, /* target MAC */
	      "\xFF\xFF\xFF\xFF\xFF\xFF", ETHER_ADDR_LEN))
    UNMATCH(*f);

  if (ntohl(arpdata.sender_ipaddr.s_addr) == 0xC0A80101) /* sender IP */
    UNMATCH(*f);
  if (ntohl(arpdata.target_ipaddr.s_addr) == 0xC0A80102) /* target IP */
    UNMATCH(*f);

  size = p - buffer;

  return size;
}

static int filter_icmp(int *f, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct icmp *icmphdr;

  if (size < sizeof(*icmphdr))
    return -1;
  icmphdr = (struct icmp *)buffer;

  /*********************************/
  /* SETUP FILTER RULE AS YOU LIKE */
  /*********************************/

  switch (icmphdr->icmp_type) { /* type */
  case ICMP_ECHO:      UNMATCH(*f); break;
  case ICMP_ECHOREPLY: UNMATCH(*f); break;
  default:             UNMATCH(*f); break;
  }
  switch (icmphdr->icmp_code) { /* code */
  default:             UNMATCH(*f); break;
  }
  if (ntohs(icmphdr->icmp_cksum) == 0) UNMATCH(*f); /* checksum */

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

static int filter_igmp(int *f, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct igmp *igmphdr;

  if (size < sizeof(*igmphdr))
    return -1;
  igmphdr = (struct igmp *)buffer;

  /*********************************/
  /* SETUP FILTER RULE AS YOU LIKE */
  /*********************************/

  switch (igmphdr->igmp_type) { /* type */
  default: UNMATCH(*f); break;
  }
  switch (igmphdr->igmp_code) { /* code */
  default: UNMATCH(*f); break;
  }
  if (ntohs(igmphdr->igmp_cksum) == 0) UNMATCH(*f); /* checksum */
  if (ntohl(igmphdr->igmp_group.s_addr) == 0xE0000001) /* group (224.0.0.1) */
    UNMATCH(*f);
  if (ntohl(igmphdr->igmp_group.s_addr) == 0xEFFFFFFF) /* (239.255.255.255) */
    UNMATCH(*f);

  s = sizeof(*igmphdr);
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

static int filter_tcp(int *f, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct tcphdr *tcphdr;

  if (size < sizeof(*tcphdr))
    return -1;
  tcphdr = (struct tcphdr *)buffer;

  /*********************************/
  /* SETUP FILTER RULE AS YOU LIKE */
  /*********************************/

  if (ntohs(tcphdr->th_sport) == 21) UNMATCH(*f); /* src port (FTP) */
  if (ntohs(tcphdr->th_dport) == 80) UNMATCH(*f); /* dst port (HTTP) */
  if (ntohl(tcphdr->th_seq  ) ==  0) UNMATCH(*f); /* seq number */
  if (ntohl(tcphdr->th_ack  ) ==  0) UNMATCH(*f); /* ack number */
  if ((tcphdr->th_off << 2)   ==  0) UNMATCH(*f); /* offset */
  if (tcphdr->th_flags) { /* flags */
    if (tcphdr->th_flags & TH_FIN ) UNMATCH(*f); /* FIN */
    if (tcphdr->th_flags & TH_SYN ) UNMATCH(*f); /* SYN */
    if (tcphdr->th_flags & TH_RST ) UNMATCH(*f); /* RST */
    if (tcphdr->th_flags & TH_PUSH) UNMATCH(*f); /* PSH */
    if (tcphdr->th_flags & TH_ACK ) UNMATCH(*f); /* ACK */
    if (tcphdr->th_flags & TH_URG ) UNMATCH(*f); /* URG */
  }
  if (ntohs(tcphdr->th_win  ) ==  0) UNMATCH(*f); /* window */
  if (ntohs(tcphdr->th_sum  ) ==  0) UNMATCH(*f); /* checksum */

  s = sizeof(*tcphdr);
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

static int filter_udp(int *f, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct udphdr *udphdr;

  if (size < sizeof(*udphdr))
    return -1;
  udphdr = (struct udphdr *)buffer;

  /*********************************/
  /* SETUP FILTER RULE AS YOU LIKE */
  /*********************************/

  if (ntohs(udphdr->uh_sport) == 53) UNMATCH(*f); /* src port (DNS) */
  if (ntohs(udphdr->uh_dport) == 67) UNMATCH(*f); /* dst port (DHCP) */
  if (ntohs(udphdr->uh_ulen ) ==  0) UNMATCH(*f); /* length */
  if (ntohs(udphdr->uh_sum  ) ==  0) UNMATCH(*f); /* checksum */

  s = sizeof(*udphdr);
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

static int filter_ip(int *f, char *buffer, int size)
{
  static char *pktbuf = NULL;
  static int bufsize = 0;
  char *p;
  int s, r = 0;
  struct ip *iphdr;
  int hdrsize, paysize;

  pktbuf = pkt_alloc_buffer(pktbuf, &bufsize, size);

  if (size < sizeof(*iphdr))
    return -1;

  memcpy(pktbuf, buffer, size);
  iphdr = (struct ip *)pktbuf;

  hdrsize = iphdr->ip_hl << 2;
  paysize = ntohs(iphdr->ip_len) - hdrsize;

  /*********************************/
  /* SETUP FILTER RULE AS YOU LIKE */
  /*********************************/

  if (ntohs(iphdr->ip_len) == 0) UNMATCH(*f); /* total size */
  if (ntohs(iphdr->ip_id ) == 0) UNMATCH(*f); /* ID */
  if (ntohs(iphdr->ip_off) == 0) UNMATCH(*f); /* fragment */
  if (      iphdr->ip_ttl  == 0) UNMATCH(*f); /* TTL */
  if (ntohs(iphdr->ip_sum) == 0) UNMATCH(*f); /* checksum */

  if (ntohl(iphdr->ip_src.s_addr) == 0xC0A80101) UNMATCH(*f); /* src IP addr */
  if (ntohl(iphdr->ip_dst.s_addr) == 0xC0A80102) UNMATCH(*f); /* dst IP addr */

  p = pktbuf + hdrsize;
  s = size   - hdrsize;

  if ((ntohs(iphdr->ip_off) & (IP_MF|IP_OFFMASK)) == 0) {
    switch (iphdr->ip_p) {
    case IPPROTO_ICMP: r = filter_icmp(f, p, s, paysize); break;
    case IPPROTO_IGMP: r = filter_igmp(f, p, s, paysize); break;
    case IPPROTO_TCP:  r = filter_tcp( f, p, s, paysize); break;
    case IPPROTO_UDP:  r = filter_udp( f, p, s, paysize); break;
    default: UNMATCH(*f); break;
    }
  }

  if (r < 0)
    return r;

  p += r;
  r = p - pktbuf;

  s = minval(hdrsize + paysize, size) - r;
  if (s > 0) {
    /* If need, attach payload here. */

    p += s;
    r += s;
  }

  return r;
}

static int filter_icmp6(int *f, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct icmp6_hdr *icmp6hdr;

  if (size < sizeof(*icmp6hdr))
    return -1;
  icmp6hdr = (struct icmp6_hdr *)buffer;

  /*********************************/
  /* SETUP FILTER RULE AS YOU LIKE */
  /*********************************/

  switch (icmp6hdr->icmp6_type) { /* type */
  case ICMP6_ECHO_REQUEST: UNMATCH(*f); break;
  case ICMP6_ECHO_REPLY:   UNMATCH(*f); break;
  default:                 UNMATCH(*f); break;
  }
  switch (icmp6hdr->icmp6_code) { /* code */
  default:                 UNMATCH(*f); break;
  }
  if (ntohs(icmp6hdr->icmp6_cksum) == 0) UNMATCH(*f); /* checksum */

  s = sizeof(*icmp6hdr);
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

static int filter_ip6(int *f, char *buffer, int size)
{
  static char *pktbuf = NULL;
  static int bufsize = 0;
  char *p;
  int s, r = 0;
  struct ip6_hdr *ip6hdr;
  int hdrsize, paysize;
  int nexthdr, exthdrsize;
  struct ip6_ext *ip6exthdr;
  struct ip6_rthdr *ip6rthdr;
  struct ip6_frag *ip6fraghdr = NULL;

  pktbuf = pkt_alloc_buffer(pktbuf, &bufsize, size);

  if (size < sizeof(*ip6hdr))
    return -1;

  memcpy(pktbuf, buffer, size);
  ip6hdr = (struct ip6_hdr *)pktbuf;

  hdrsize = sizeof(struct ip6_hdr);
  paysize = ntohs(ip6hdr->ip6_plen);

  /*********************************/
  /* SETUP FILTER RULE AS YOU LIKE */
  /*********************************/

  if (ip6hdr->ip6_hlim == 0) UNMATCH(*f); /* hop limit */

  if (!memcmp(&ip6hdr->ip6_src.s6_addr, /* src IPv6 addr */
	      "\xFE\xC0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01",
	      sizeof(struct in6_addr))) UNMATCH(*f);
  if (!memcmp(&ip6hdr->ip6_dst.s6_addr, /* dst IPv6 addr */
	      "\xFE\xC0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02",
	      sizeof(struct in6_addr))) UNMATCH(*f);

  p = pktbuf + hdrsize;
  s = size   - hdrsize;

  nexthdr = ip6hdr->ip6_nxt;

  while (1) {
    exthdrsize = 0;
    switch (nexthdr) {
    case IPPROTO_HOPOPTS:
    case IPPROTO_DSTOPTS:
      if (s < sizeof(*ip6exthdr))
	return -1;
      ip6exthdr = (struct ip6_ext *)p;
      nexthdr = ip6exthdr->ip6e_nxt;
      exthdrsize = (ip6exthdr->ip6e_len + 1) << 3;
      break;
    case IPPROTO_ROUTING:
      if (s < sizeof(*ip6rthdr))
	return -1;
      ip6rthdr = (struct ip6_rthdr *)p;
      nexthdr = ip6rthdr->ip6r_nxt;
      exthdrsize = (ip6rthdr->ip6r_len + 1) << 3;
      break;
    case IPPROTO_FRAGMENT:
      if (s < sizeof(*ip6fraghdr))
	return -1;
      ip6fraghdr = (struct ip6_frag *)p;
      nexthdr = ip6fraghdr->ip6f_nxt;
      exthdrsize = sizeof(*ip6fraghdr);
      break;
    case IPPROTO_NONE:
    default:
      break;
    }
    if (exthdrsize == 0)
      break;
    if (s < exthdrsize)
      return -1;
    p       += exthdrsize;
    s       -= exthdrsize;
    hdrsize += exthdrsize;
    paysize -= exthdrsize;
  }

  if (ip6fraghdr == NULL) {
    switch (nexthdr) {
    case IPPROTO_ICMPV6: r = filter_icmp6(f, p, s, paysize); break;
    case IPPROTO_TCP:    r = filter_tcp(  f, p, s, paysize); break;
    case IPPROTO_UDP:    r = filter_udp(  f, p, s, paysize); break;
    default: UNMATCH(*f); break;
    }
  }

  if (r < 0)
    return r;

  p += r;
  r = p - pktbuf;

  s = minval(hdrsize + paysize, size) - r;
  if (s > 0) {
    /* If need, attach payload here. */

    p += s;
    r += s;
  }

  return r;
}

int pkt_filter_ethernet(char *buffer, int size)
{
  int f = 0;
  char *p;
  int s, r = 0;
  struct ether_header ehdr;
  struct {
    pkt_uint16 tag;
    pkt_uint16 proto;
  } vlantag;
  int type;

  if (size < ETHER_HDR_LEN)
    return -1;
  memcpy(&ehdr, buffer, ETHER_HDR_LEN);

  /*********************************/
  /* SETUP FILTER RULE AS YOU LIKE */
  /*********************************/

  if (!memcmp(ehdr.ether_shost, "\xFF\xFF\xFF\xFF\xFF\xFF", /* src MAC addr */
	      ETHER_ADDR_LEN)) UNMATCH(f);
  if (!memcmp(ehdr.ether_dhost, "\xFF\xFF\xFF\xFF\xFF\xFF", /* dst MAC addr */
	      ETHER_ADDR_LEN)) UNMATCH(f);
  if (ntohs(ehdr.ether_type) == 0) /* type */
    UNMATCH(f);

  type = ntohs(ehdr.ether_type);
  p = buffer + ETHER_HDR_LEN;
  s = size   - ETHER_HDR_LEN;

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86DD
#endif

  while (type == ETHERTYPE_VLAN) {
    if (s < sizeof(vlantag))
      return -1;
    memcpy(&vlantag, p, sizeof(vlantag));
    if (ntohs(vlantag.tag) == 0) /* VLAN tag */
      UNMATCH(f);
    if (ntohs(vlantag.proto) == 0) /* VLAN protocol */
      UNMATCH(f);
    type = ntohs(vlantag.proto);
    p += sizeof(vlantag);
    s -= sizeof(vlantag);
  }

  switch (type) {
  case ETHERTYPE_ARP:  r = filter_arp(&f, p, s); break;
  case ETHERTYPE_IP:   r = filter_ip( &f, p, s); break;
  case ETHERTYPE_IPV6: r = filter_ip6(&f, p, s); break;
  default: UNMATCH(f); break;
  }

  if (r < 0)
    return r;

  p += r;
  r = p - buffer;

  s = size - r;
  if (s > 0) {
    /* If need, attach payload here. */

    p += s;
    r += s;
  }

  return (f == 0) ? FILTER_RULE_UNMATCH : FILTER_RULE_MATCH;
}
