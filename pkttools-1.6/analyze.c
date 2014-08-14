#ifdef __linux__
#define _BSD_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
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

#include "analyze.h"
#include "lib.h"

static int analyze_arp(FILE *fp, char *buffer, int size)
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

  fprintf(fp, "ARP");
  fprintf(fp, "\toperation\t: %d\n", ntohs(arphdr.ar_op));
  fprintf(fp, "\thrd/prt (size)\t: %d / 0x%04x (%d / %d)\n",
	  ntohs(arphdr.ar_hrd), ntohs(arphdr.ar_pro),
	  arphdr.ar_hln, arphdr.ar_pln);

  if ((ntohs(arphdr.ar_hrd) != ARPHRD_ETHER) ||
      (ntohs(arphdr.ar_pro) != ETHERTYPE_IP) ||
      (arphdr.ar_hln != ETHER_ADDR_LEN) ||
      (arphdr.ar_pln != sizeof(in_addr_t)))
    return -1;

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

  fprintf(fp, "\tsender MAC/IP\t: %s    \t/ %s\n",
	  ether_ntoa(arpdata.sender_macaddr.addr),
	  inet_ntoa(arpdata.sender_ipaddr));
  fprintf(fp, "\ttarget MAC/IP\t: %s    \t/ %s\n",
	  ether_ntoa(arpdata.target_macaddr.addr),
	  inet_ntoa(arpdata.target_ipaddr));

  size = p - buffer;

  return size;
}

static int analyze_icmp(FILE *fp, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct icmp *icmphdr;

  if (size < sizeof(*icmphdr))
    return -1;
  icmphdr = (struct icmp *)buffer;

  fprintf(fp, "ICMP");
  fprintf(fp, "\ttotal size\t: %d bytes\n", total_size);
  fprintf(fp, "\ttype/code\t: %d / %d\n",
	  icmphdr->icmp_type, icmphdr->icmp_code);
  fprintf(fp, "\tchecksum\t: 0x%04x\n", ntohs(icmphdr->icmp_cksum));

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

static int analyze_igmp(FILE *fp, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct igmp *igmphdr;

  if (size < sizeof(*igmphdr))
    return -1;
  igmphdr = (struct igmp *)buffer;

  fprintf(fp, "IGMP");
  fprintf(fp, "\ttotal size\t: %d bytes\n", total_size);
  fprintf(fp, "\ttype/code\t: %d / %d\n",
	  igmphdr->igmp_type, igmphdr->igmp_code);
  fprintf(fp, "\tchecksum\t: 0x%04x\n", ntohs(igmphdr->igmp_cksum));
  fprintf(fp, "\tgroup\t\t: %s\n", inet_ntoa(igmphdr->igmp_group));

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

static int analyze_tcp(FILE *fp, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct tcphdr *tcphdr;

  if (size < sizeof(*tcphdr))
    return -1;
  tcphdr = (struct tcphdr *)buffer;

  fprintf(fp, "TCP");
  fprintf(fp, "\ttotal size\t: %d bytes\n", total_size);
  fprintf(fp, "\tsrc/dst port\t: %d / %d\n",
	  ntohs(tcphdr->th_sport), ntohs(tcphdr->th_dport));
  fprintf(fp, "\tseq/ack number\t: %u / %u\n",
	  ntohl(tcphdr->th_seq), ntohl(tcphdr->th_ack));
  fprintf(fp, "\toffset/window\t: %d / %d\n",
	  (tcphdr->th_off << 2), ntohs(tcphdr->th_win));
  fprintf(fp, "\tchecksum/flags\t: 0x%04x / ", ntohs(tcphdr->th_sum));
  fprintf(fp, "0x%02x ( ", tcphdr->th_flags);
  if (tcphdr->th_flags & TH_FIN ) fprintf(fp, "FIN ");
  if (tcphdr->th_flags & TH_SYN ) fprintf(fp, "SYN ");
  if (tcphdr->th_flags & TH_RST ) fprintf(fp, "RST ");
  if (tcphdr->th_flags & TH_PUSH) fprintf(fp, "PSH ");
  if (tcphdr->th_flags & TH_ACK ) fprintf(fp, "ACK ");
  if (tcphdr->th_flags & TH_URG ) fprintf(fp, "URG ");
  fprintf(fp, ")\n");

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

static int analyze_udp(FILE *fp, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct udphdr *udphdr;

  if (size < sizeof(*udphdr))
    return -1;
  udphdr = (struct udphdr *)buffer;

  fprintf(fp, "UDP");
  fprintf(fp, "\ttotal size\t: %d bytes\n", total_size);
  fprintf(fp, "\tsrc/dst port\t: %d / %d\n",
	  ntohs(udphdr->uh_sport), ntohs(udphdr->uh_dport));
  fprintf(fp, "\tlength/checksum\t: %d / 0x%04x\n",
	  ntohs(udphdr->uh_ulen), ntohs(udphdr->uh_sum));

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

static int analyze_ip(FILE *fp, char *buffer, int size)
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

  fprintf(fp, "IP");
  fprintf(fp, "\thead/total size\t: %d / %d bytes\n",
	  hdrsize, ntohs(iphdr->ip_len));
  fprintf(fp, "\tID/fragment\t: 0x%04x / 0x%04x\n",
	  ntohs(iphdr->ip_id), ntohs(iphdr->ip_off));
  fprintf(fp, "\tTTL/protocol\t: %d / %d\n", iphdr->ip_ttl, iphdr->ip_p);
  fprintf(fp, "\tchecksum\t: 0x%04x\n", ntohs(iphdr->ip_sum));
  fprintf(fp, "\tsrc/dst addr\t: %s / ", inet_ntoa(iphdr->ip_src));
  fprintf(fp, "%s\n", inet_ntoa(iphdr->ip_dst));

  p = pktbuf + hdrsize;
  s = size   - hdrsize;

  if ((ntohs(iphdr->ip_off) & (IP_MF|IP_OFFMASK)) == 0) {
    switch (iphdr->ip_p) {
    case IPPROTO_ICMP: r = analyze_icmp(fp, p, s, paysize); break;
    case IPPROTO_IGMP: r = analyze_igmp(fp, p, s, paysize); break;
    case IPPROTO_TCP:  r = analyze_tcp( fp, p, s, paysize); break;
    case IPPROTO_UDP:  r = analyze_udp( fp, p, s, paysize); break;
    default: break;
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

static int analyze_icmp6(FILE *fp, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct icmp6_hdr *icmp6hdr;

  if (size < sizeof(*icmp6hdr))
    return -1;
  icmp6hdr = (struct icmp6_hdr *)buffer;

  fprintf(fp, "ICMPv6");
  fprintf(fp, "\ttotal size\t: %d bytes\n", total_size);
  fprintf(fp, "\ttype/code\t: %d / %d\n",
	  icmp6hdr->icmp6_type, icmp6hdr->icmp6_code);
  fprintf(fp, "\tchecksum\t: 0x%04x\n", ntohs(icmp6hdr->icmp6_cksum));

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

static int analyze_ip6(FILE *fp, char *buffer, int size)
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
  char addrs[INET6_ADDRSTRLEN];

  pktbuf = pkt_alloc_buffer(pktbuf, &bufsize, size);

  if (size < sizeof(*ip6hdr))
    return -1;

  memcpy(pktbuf, buffer, size);
  ip6hdr = (struct ip6_hdr *)pktbuf;

  hdrsize = sizeof(struct ip6_hdr);
  paysize = ntohs(ip6hdr->ip6_plen);

  fprintf(fp, "IPv6");
  fprintf(fp, "\tpayload size\t: %d bytes\n", paysize);
  fprintf(fp, "\thop limit\t: %d\n", ip6hdr->ip6_hlim);
  if (inet_ntop(AF_INET6, &ip6hdr->ip6_src, addrs, sizeof(addrs)) != NULL)
    fprintf(fp, "\tsrc addr\t: %s\n", addrs);
  if (inet_ntop(AF_INET6, &ip6hdr->ip6_dst, addrs, sizeof(addrs)) != NULL)
    fprintf(fp, "\tdst addr\t: %s\n", addrs);

  p = pktbuf + hdrsize;
  s = size   - hdrsize;

  nexthdr = ip6hdr->ip6_nxt;

  while (1) {
    fprintf(fp, "\tnext header\t: %d\n", nexthdr);
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
    fprintf(fp, "\texthdr size\t: %d bytes\n", exthdrsize);
    p       += exthdrsize;
    s       -= exthdrsize;
    hdrsize += exthdrsize;
    paysize -= exthdrsize;
  }

  if (ip6fraghdr == NULL) {
    switch (nexthdr) {
    case IPPROTO_ICMPV6: r = analyze_icmp6(fp, p, s, paysize); break;
    case IPPROTO_TCP:    r = analyze_tcp(  fp, p, s, paysize); break;
    case IPPROTO_UDP:    r = analyze_udp(  fp, p, s, paysize); break;
    default: break;
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

int pkt_analyze_ethernet(FILE *fp, char *buffer, int size, struct timeval *tm)
{
  char *p;
  int s, r = 0;
  struct ether_header ehdr;
  struct {
    pkt_uint16 tag;
    pkt_uint16 proto;
  } vlantag;
  int type;
  static int count = 0;

  count++;
  fprintf(fp, "-- %d --\n", count);
  fprintf(fp, "received: %d bytes    %d.%06d %s", size,
	  (int)tm->tv_sec, (int)tm->tv_usec, ctime(&tm->tv_sec));
  if (size < ETHER_HDR_LEN)
    return -1;
  memcpy(&ehdr, buffer, ETHER_HDR_LEN);

  fprintf(fp, "%s ->", ether_ntoa((struct ether_addr *)ehdr.ether_shost));
  fprintf(fp, " %s  ", ether_ntoa((struct ether_addr *)ehdr.ether_dhost));

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
    fprintf(fp, "(VLAN tag: 0x%04x) ", ntohs(vlantag.tag));
    type = ntohs(vlantag.proto);
    p += sizeof(vlantag);
    s -= sizeof(vlantag);
  }

  fprintf(fp, "(type: 0x%04x)\n", type);

  switch (type) {
  case ETHERTYPE_ARP:  r = analyze_arp(fp, p, s); break;
  case ETHERTYPE_IP:   r = analyze_ip( fp, p, s); break;
  case ETHERTYPE_IPV6: r = analyze_ip6(fp, p, s); break;
  default: break;
  }

  fprintf(fp, "==\n");
  fflush(fp);

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

  return r;
}
