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

#include "change.h"
#include "lib.h"

static int change_arp(char *buffer, int size)
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
  /* SETUP CHANGE RULE AS YOU LIKE */
  /*********************************/

  switch (ntohs(arphdr.ar_op)) { /* operation */
  case ARPOP_REQUEST:
  case ARPOP_REPLY:
  default:
    arphdr.ar_op = htons(ntohs(arphdr.ar_op));
    break;
  }
  switch (ntohs(arphdr.ar_hrd)) { /* hardware */
  case ARPHRD_ETHER:
  default:
    arphdr.ar_hrd = htons(ntohs(arphdr.ar_hrd));
    break;
  }
  switch (ntohs(arphdr.ar_pro)) { /* protocol */
  case ETHERTYPE_IP:
  default:
    arphdr.ar_pro = htons(ntohs(arphdr.ar_pro));
    break;
  }
  switch (arphdr.ar_hln) { /* hard size */
  case ETHER_ADDR_LEN:
  default:
    arphdr.ar_hln = arphdr.ar_hln;
    break;
  }
  switch (arphdr.ar_pln) { /* proto size */
  case sizeof(in_addr_t):
  default:
    arphdr.ar_pln = arphdr.ar_pln;
    break;
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
  /* SETUP CHANGE RULE AS YOU LIKE */
  /*********************************/

  /*if (!memcmp(arpdata.sender_macaddr.octet, sender MAC 
	      "\xFF\xFF\xFF\xFF\xFF\xFF", ETHER_ADDR_LEN))
    memcpy(arpdata.sender_macaddr.octet,
	   "\xFF\xFF\xFF\xFF\xFF\xFF", ETHER_ADDR_LEN);
  if (!memcmp(arpdata.target_macaddr.octet,  target MAC //
	      "\xFF\xFF\xFF\xFF\xFF\xFF", ETHER_ADDR_LEN))
    memcpy(arpdata.target_macaddr.octet,
	   "\FF\xFF\xFF\xFF\xFF\xFF", ETHER_ADDR_LEN);*/    
switch(ntohs(arphdr.ar_op)){
  case ARPOP_REQUEST:
 memcpy(arpdata.sender_macaddr.octet,
 	 "\xB8\x27\xEB\x5B\xA0\xC3",ETHER_ADDR_LEN); 
 sleep(1);

 break;
  case ARPOP_REPLY:
    memcpy(arpdata.target_macaddr.octet,"\xB8\x27\xEB\x5B\xA0\xC3",ETHER_ADDR_LEN);
    sleep(1);
    break;
 }
if (ntohl(arpdata.sender_ipaddr.s_addr) == 0xC0A80101) /* sender IP */
    arpdata.sender_ipaddr.s_addr = htonl(ntohl(arpdata.sender_ipaddr.s_addr));
  if (ntohl(arpdata.target_ipaddr.s_addr) == 0xC0A80102) /* target IP */
    arpdata.target_ipaddr.s_addr = htonl(ntohl(arpdata.target_ipaddr.s_addr));

  memcpy(sip, &arpdata.sender_ipaddr.s_addr, sizeof(in_addr_t));
  memcpy(tip, &arpdata.target_ipaddr.s_addr, sizeof(in_addr_t));

  memcpy(buffer, &arphdr, sizeof(arphdr));

  size = p - buffer;

  return size;
}

static int change_icmp(char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct icmp *icmphdr;
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
  if (size < sizeof(*icmphdr))
   return -1;
  icmphdr = (struct icmp *)buffer;

  /********************************/
  /* SETUP CHANGE RULE AS YOU LIKE */
  /*********************************/

  switch (icmphdr->icmp_type) { /* type */
  case ICMP_ECHO: 
    memcpy(ehdr.ether_shost,"\xB8\x27\xEB\x5B\xA0\xC3",ETHER_ADDR_LEN);
    memcpy(ehdr.ether_dhost,"\x28\xD2\x44\x63\xF0\xC1",ETHER_ADDR_LEN);
    break;
  case ICMP_ECHOREPLY:
    memcpy(ehdr.ether_shost,"\xB8\x27\xEB\x5B\xA0\xC3",ETHER_ADDR_LEN);
    memcpy(ehdr.ether_dhost,"\x00\x0B\x97\xDC\xC6\x9D",ETHER_ADDR_LEN);
    break;
 default:
    icmphdr->icmp_type = icmphdr->icmp_type;
    break;
  }
  switch (icmphdr->icmp_code) { /* code */
  default:
    icmphdr->icmp_code = icmphdr->icmp_code;
    break;
  }
  if (ntohs(icmphdr->icmp_cksum) == 0) /* checksum */
    icmphdr->icmp_cksum = htons(ntohs(icmphdr->icmp_cksum));

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

static int change_igmp(char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct igmp *igmphdr;

  if (size < sizeof(*igmphdr))
    return -1;
  igmphdr = (struct igmp *)buffer;

  /*********************************/
  /* SETUP CHANGE RULE AS YOU LIKE */
  /*********************************/

  switch (igmphdr->igmp_type) { /* type */
  default:
    igmphdr->igmp_type = igmphdr->igmp_type;
    break;
  }
  switch (igmphdr->igmp_code) { /* code */
  default:
    igmphdr->igmp_code = igmphdr->igmp_code;
    break;
  }
  if (ntohs(igmphdr->igmp_cksum) == 0) /* checksum */
    igmphdr->igmp_cksum = htons(ntohs(igmphdr->igmp_cksum));
  if (ntohl(igmphdr->igmp_group.s_addr) == 0xE0000001) /* group (224.0.0.1) */
    igmphdr->igmp_group.s_addr = htonl(ntohl(igmphdr->igmp_group.s_addr));
  if (ntohl(igmphdr->igmp_group.s_addr) == 0xEFFFFFFF) /* (239.255.255.255) */
    igmphdr->igmp_group.s_addr = htonl(ntohl(igmphdr->igmp_group.s_addr));

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

static int change_tcp(char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct tcphdr *tcphdr;

  if (size < sizeof(*tcphdr))
    return -1;
  tcphdr = (struct tcphdr *)buffer;

  /*********************************/
  /* SETUP CHANGE RULE AS YOU LIKE */
  /*********************************/

  if (ntohs(tcphdr->th_sport) == 21) /* src port (FTP) */
    tcphdr->th_sport = htons(ntohs(tcphdr->th_sport));
  if (ntohs(tcphdr->th_dport) == 80) /* dst port (HTTP) */
    tcphdr->th_dport = htons(ntohs(tcphdr->th_dport));
  if (ntohl(tcphdr->th_seq  ) ==  0) /* seq number */
    tcphdr->th_seq = htonl(ntohl(tcphdr->th_seq));
  if (ntohl(tcphdr->th_ack  ) ==  0) /* ack number */
    tcphdr->th_ack = htonl(ntohl(tcphdr->th_ack));
  if ((tcphdr->th_off << 2)   ==  0) /* offset */
    tcphdr->th_off = tcphdr->th_off;
  if (tcphdr->th_flags) { /* flags */
    if (tcphdr->th_flags & TH_FIN ) tcphdr->th_flags |= TH_FIN;  /* FIN */
    if (tcphdr->th_flags & TH_SYN ) tcphdr->th_flags |= TH_SYN;  /* SYN */
    if (tcphdr->th_flags & TH_RST ) tcphdr->th_flags |= TH_RST;  /* RST */
    if (tcphdr->th_flags & TH_PUSH) tcphdr->th_flags |= TH_PUSH; /* PSH */
    if (tcphdr->th_flags & TH_ACK ) tcphdr->th_flags |= TH_ACK;  /* ACK */
    if (tcphdr->th_flags & TH_URG ) tcphdr->th_flags |= TH_URG;  /* URG */
  }
  if (ntohs(tcphdr->th_win  ) ==  0) /* window */
    tcphdr->th_win = htons(ntohs(tcphdr->th_win));
  if (ntohs(tcphdr->th_sum  ) ==  0) /* checksum */
    tcphdr->th_sum = htons(ntohs(tcphdr->th_sum));

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

static int change_udp(char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct udphdr *udphdr;

  if (size < sizeof(*udphdr))
    return -1;
  udphdr = (struct udphdr *)buffer;

  /*********************************/
  /* SETUP CHANGE RULE AS YOU LIKE */
  /*********************************/

  if (ntohs(udphdr->uh_sport) == 53) /* src port (DNS) */
    udphdr->uh_sport = htons(ntohs(udphdr->uh_sport));
  if (ntohs(udphdr->uh_dport) == 67) /* dst port (DHCP) */
    udphdr->uh_dport = htons(ntohs(udphdr->uh_dport));
  if (ntohs(udphdr->uh_ulen ) ==  0) /* length */
    udphdr->uh_ulen = htons(ntohs(udphdr->uh_ulen));
  if (ntohs(udphdr->uh_sum  ) ==  0) /* checksum */
    udphdr->uh_sum = htons(ntohs(udphdr->uh_sum));

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

static int change_ip(char *buffer, int size)
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
  /* SETUP CHANGE RULE AS YOU LIKE */
  /*********************************/

  if (ntohs(iphdr->ip_len) == 0) /* total size */
    iphdr->ip_len = htons(ntohs(iphdr->ip_len));
  if (ntohs(iphdr->ip_id ) == 0) /* ID */
    iphdr->ip_id = htons(ntohs(iphdr->ip_id));
  if (ntohs(iphdr->ip_off) == 0) /* fragment */
    iphdr->ip_off = htons(ntohs(iphdr->ip_off));
  if (      iphdr->ip_ttl  == 0) /* TTL */
    iphdr->ip_ttl = iphdr->ip_ttl;
  if (ntohs(iphdr->ip_sum) == 0) /* checksum */
    iphdr->ip_sum = htons(ntohs(iphdr->ip_sum));

  if (ntohl(iphdr->ip_src.s_addr) == 0xC0A80101) /* src IP addr */
    iphdr->ip_src.s_addr = htonl(ntohl(iphdr->ip_src.s_addr));
  if (ntohl(iphdr->ip_dst.s_addr) == 0xC0A80102) /* dst IP addr */
    iphdr->ip_dst.s_addr = htonl(ntohl(iphdr->ip_dst.s_addr));

  p = pktbuf + hdrsize;
  s = size   - hdrsize;

  if ((ntohs(iphdr->ip_off) & (IP_MF|IP_OFFMASK)) == 0) {
    switch (iphdr->ip_p) {
    case IPPROTO_ICMP: r = change_icmp(p, s, paysize); break;
    case IPPROTO_IGMP: r = change_igmp(p, s, paysize); break;
    case IPPROTO_TCP:  r = change_tcp( p, s, paysize); break;
    case IPPROTO_UDP:  r = change_udp( p, s, paysize); break;
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

  memcpy(buffer, pktbuf, r);

  return r;
}

static int change_icmp6(char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct icmp6_hdr *icmp6hdr;

  if (size < sizeof(*icmp6hdr))
    return -1;
  icmp6hdr = (struct icmp6_hdr *)buffer;

  /*********************************/
  /* SETUP CHANGE RULE AS YOU LIKE */
  /*********************************/

  switch (icmp6hdr->icmp6_type) { /* type */
  case ICMP6_ECHO_REQUEST:
  case ICMP6_ECHO_REPLY:
  default:
    icmp6hdr->icmp6_type = icmp6hdr->icmp6_type;
    break;
  }
  switch (icmp6hdr->icmp6_code) { /* code */
  default:
    icmp6hdr->icmp6_code = icmp6hdr->icmp6_code;
    break;
  }
  if (ntohs(icmp6hdr->icmp6_cksum) == 0) /* checksum */
    icmp6hdr->icmp6_cksum = htons(ntohs(icmp6hdr->icmp6_cksum));

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

static int change_ip6(char *buffer, int size)
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
  /* SETUP CHANGE RULE AS YOU LIKE */
  /*********************************/

  if (ip6hdr->ip6_hlim == 0) /* hop limit */
    ip6hdr->ip6_hlim = ip6hdr->ip6_hlim;

  if (!memcmp(&ip6hdr->ip6_src.s6_addr, /* src IPv6 addr */
	      "\xFE\xC0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01",
	      sizeof(struct in6_addr)))
    memcpy(&ip6hdr->ip6_src.s6_addr,
	   "\xFE\xC0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01",
	   sizeof(struct in6_addr));
  if (!memcmp(&ip6hdr->ip6_dst.s6_addr, /* dst IPv6 addr */
	      "\xFE\xC0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02",
	      sizeof(struct in6_addr)))
    memcpy(&ip6hdr->ip6_dst.s6_addr,
	   "\xFE\xC0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02",
	   sizeof(struct in6_addr));

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
    case IPPROTO_ICMPV6: r = change_icmp6(p, s, paysize); break;
    case IPPROTO_TCP:    r = change_tcp(  p, s, paysize); break;
    case IPPROTO_UDP:    r = change_udp(  p, s, paysize); break;
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

  memcpy(buffer, pktbuf, r);

  return r;
}

int pkt_change_ethernet(char *buffer, int size)
{
  char *p;
  int s, r = 0;
  struct ether_header ehdr;
  struct {
    pkt_uint16 tag;
    pkt_uint16 proto;
  } vlantag;
  int type;

  if (size < ETHER_HDR_LEN)
    return -1;*
  memcpy(&ehdr, buffer, ETHER_HDR_LEN);

  /*********************************/
  /* SETUP CHANGE RULE AS YOU LIKE */
  /*********************************/

  if (!memcmp(ehdr.ether_shost, "\xFF\xFF\xFF\xFF\xFF\xFF", /* src MAC addr */
	      ETHER_ADDR_LEN))
    memcpy(ehdr.ether_shost, "\xFF\xFF\xFF\xFF\xFF\xFF", ETHER_ADDR_LEN);
  if (!memcmp(ehdr.ether_dhost, "\xFF\xFF\xFF\xFF\xFF\xFF", /* dst MAC addr */
	      ETHER_ADDR_LEN))
    memcpy(ehdr.ether_dhost, "\xFF\xFF\xFF\xFF\xFF\xFF", ETHER_ADDR_LEN);

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
      vlantag.tag = htons(ntohs(vlantag.tag));
    if (ntohs(vlantag.proto) == 0) /* VLAN protocol */
      vlantag.proto = htons(ntohs(vlantag.proto));
    memcpy(p, &vlantag, sizeof(vlantag));
    type = ntohs(vlantag.proto);
    p += sizeof(vlantag);
    s -= sizeof(vlantag);
  }

  ehdr.ether_type = htons(type);

  switch (type) {
  case ETHERTYPE_ARP:  r = change_arp(p, s); break;
  case ETHERTYPE_IP:   r = change_ip( p, s); break;
  case ETHERTYPE_IPV6: r = change_ip6(p, s); break;
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
