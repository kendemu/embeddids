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

#include "asm_val.h"
#include "asm_field.h"
#include "asm_entry.h"
#include "asm_list.h"
#include "disasm.h"
#include "lib.h"

static int disasm_arp(pkt_asm_list_t list, char *buffer, int size)
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
  pkt_asm_val_t val;
  struct in_addr ipaddr;

  if (size < sizeof(arphdr))
    return -1;
  memcpy(&arphdr, buffer, sizeof(arphdr));

  pkt_asm_list_add_val(list, PKT_ASM_FIELD_ARP_HARDWARE,
		       pkt_asm_val_create_integer(ntohs(arphdr.ar_hrd)));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_ARP_PROTOCOL,
		       pkt_asm_val_create_integer(ntohs(arphdr.ar_pro)));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_ARP_HARDWARE_SIZE,
		       pkt_asm_val_create_integer(arphdr.ar_hln));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_ARP_PROTOCOL_SIZE,
		       pkt_asm_val_create_integer(arphdr.ar_pln));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_ARP_OPERATION,
		       pkt_asm_val_create_integer(ntohs(arphdr.ar_op)));

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

  val = pkt_asm_val_create_macaddr(arpdata.sender_macaddr.addr);
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_ARP_SENDER_MACADDR, val);

  ipaddr.s_addr = ntohl(arpdata.sender_ipaddr.s_addr);
  val = pkt_asm_val_create_ipaddr(&ipaddr);
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_ARP_SENDER_IPADDR, val);

  val = pkt_asm_val_create_macaddr(arpdata.target_macaddr.addr);
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_ARP_TARGET_MACADDR, val);

  ipaddr.s_addr = ntohl(arpdata.target_ipaddr.s_addr);
  val = pkt_asm_val_create_ipaddr(&ipaddr);
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_ARP_TARGET_IPADDR, val);

  size = p - buffer;

  return size;
}

static int disasm_icmp(pkt_asm_list_t list, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct icmp *icmphdr;

  if (size < sizeof(*icmphdr))
    return -1;
  icmphdr = (struct icmp *)buffer;

  pkt_asm_list_add_val(list, PKT_ASM_FIELD_ICMP_TYPE,
		       pkt_asm_val_create_integer(icmphdr->icmp_type));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_ICMP_CODE,
		       pkt_asm_val_create_integer(icmphdr->icmp_code));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_ICMP_CHECKSUM,
		       pkt_asm_val_create_integer(ntohs(icmphdr->icmp_cksum)));

  s = sizeof(*icmphdr);
  p += s;
  r += s;

  s = minval(total_size, size) - r;
  if (s > 0) {
    pkt_asm_list_add_val(list, PKT_ASM_FIELD_ICMP_DATA,
			 pkt_asm_val_create_binary(s, p));
    p += s;
    r += s;
  }

  return r;
}

static int disasm_igmp(pkt_asm_list_t list, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct igmp *igmphdr;
  struct in_addr ipaddr;

  if (size < sizeof(*igmphdr))
    return -1;
  igmphdr = (struct igmp *)buffer;

  pkt_asm_list_add_val(list, PKT_ASM_FIELD_IGMP_TYPE,
		       pkt_asm_val_create_integer(igmphdr->igmp_type));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_IGMP_CODE,
		       pkt_asm_val_create_integer(igmphdr->igmp_code));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_IGMP_CHECKSUM,
		       pkt_asm_val_create_integer(ntohs(igmphdr->igmp_cksum)));
  ipaddr.s_addr = ntohl(igmphdr->igmp_group.s_addr);
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_IGMP_GROUP,
		       pkt_asm_val_create_ipaddr(&ipaddr));

  s = sizeof(*igmphdr);
  p += s;
  r += s;

  s = minval(total_size, size) - r;
  if (s > 0) {
    pkt_asm_list_add_val(list, PKT_ASM_FIELD_IGMP_DATA,
			 pkt_asm_val_create_binary(s, p));
    p += s;
    r += s;
  }

  return r;
}

static int disasm_tcp(pkt_asm_list_t list, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct tcphdr *tcphdr;

  if (size < sizeof(*tcphdr))
    return -1;
  tcphdr = (struct tcphdr *)buffer;

  pkt_asm_list_add_val(list, PKT_ASM_FIELD_TCP_SRC_PORT,
		       pkt_asm_val_create_integer(ntohs(tcphdr->th_sport)));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_TCP_DST_PORT,
		       pkt_asm_val_create_integer(ntohs(tcphdr->th_dport)));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_TCP_SEQ_NUMBER,
		       pkt_asm_val_create_integer(ntohl(tcphdr->th_seq)));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_TCP_ACK_NUMBER,
		       pkt_asm_val_create_integer(ntohl(tcphdr->th_ack)));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_TCP_OFFSET,
		       pkt_asm_val_create_integer(tcphdr->th_off << 2));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_TCP_FLAGS,
		       pkt_asm_val_create_integer(tcphdr->th_flags));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_TCP_WINDOW,
		       pkt_asm_val_create_integer(ntohs(tcphdr->th_win)));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_TCP_CHECKSUM,
		       pkt_asm_val_create_integer(ntohs(tcphdr->th_sum)));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_TCP_URGENT,
		       pkt_asm_val_create_integer(ntohs(tcphdr->th_urp)));

  s = sizeof(*tcphdr);
  p += s;
  r += s;

  s = minval(total_size, size) - r;
  if (s > 0) {
    pkt_asm_list_add_val(list, PKT_ASM_FIELD_TCP_DATA,
			 pkt_asm_val_create_binary(s, p));
    p += s;
    r += s;
  }

  return r;
}

static int disasm_udp(pkt_asm_list_t list, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct udphdr *udphdr;

  if (size < sizeof(*udphdr))
    return -1;
  udphdr = (struct udphdr *)buffer;

  pkt_asm_list_add_val(list, PKT_ASM_FIELD_UDP_SRC_PORT,
		       pkt_asm_val_create_integer(ntohs(udphdr->uh_sport)));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_UDP_DST_PORT,
		       pkt_asm_val_create_integer(ntohs(udphdr->uh_dport)));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_UDP_SIZE,
		       pkt_asm_val_create_integer(ntohs(udphdr->uh_ulen)));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_UDP_CHECKSUM,
		       pkt_asm_val_create_integer(ntohs(udphdr->uh_sum)));

  s = sizeof(*udphdr);
  p += s;
  r += s;

  s = minval(total_size, size) - r;
  if (s > 0) {
    pkt_asm_list_add_val(list, PKT_ASM_FIELD_UDP_DATA,
			 pkt_asm_val_create_binary(s, p));
    p += s;
    r += s;
  }

  return r;
}

static int disasm_ip(pkt_asm_list_t list, char *buffer, int size)
{
  static char *pktbuf = NULL;
  static int bufsize = 0;
  char *p;
  int s, r = 0;
  struct ip *iphdr;
  int hdrsize, paysize;
  struct in_addr ipaddr;

  pktbuf = pkt_alloc_buffer(pktbuf, &bufsize, size);

  if (size < sizeof(*iphdr))
    return -1;

  memcpy(pktbuf, buffer, size);
  iphdr = (struct ip *)pktbuf;

  hdrsize = iphdr->ip_hl << 2;
  paysize = ntohs(iphdr->ip_len) - hdrsize;

  pkt_asm_list_add_val(list, PKT_ASM_FIELD_IP_VERSION,
		       pkt_asm_val_create_integer(iphdr->ip_v));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_IP_HEADER_SIZE,
		       pkt_asm_val_create_integer(hdrsize));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_IP_TOS,
		       pkt_asm_val_create_integer(iphdr->ip_tos));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_IP_TOTAL_SIZE,
		       pkt_asm_val_create_integer(ntohs(iphdr->ip_len)));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_IP_ID,
		       pkt_asm_val_create_integer(ntohs(iphdr->ip_id)));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_IP_FRAGMENT,
		       pkt_asm_val_create_integer(ntohs(iphdr->ip_off)));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_IP_TTL,
		       pkt_asm_val_create_integer(iphdr->ip_ttl));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_IP_PROTOCOL,
		       pkt_asm_val_create_integer(iphdr->ip_p));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_IP_CHECKSUM,
		       pkt_asm_val_create_integer(ntohs(iphdr->ip_sum)));
  ipaddr.s_addr = ntohl(iphdr->ip_src.s_addr);
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_IP_SRC_ADDR,
		       pkt_asm_val_create_ipaddr(&ipaddr));
  ipaddr.s_addr = ntohl(iphdr->ip_dst.s_addr);
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_IP_DST_ADDR,
		       pkt_asm_val_create_ipaddr(&ipaddr));

  p = pktbuf + hdrsize;
  s = size   - hdrsize;

  if ((ntohs(iphdr->ip_off) & (IP_MF|IP_OFFMASK)) == 0) {
    switch (iphdr->ip_p) {
    case IPPROTO_ICMP: r = disasm_icmp(list, p, s, paysize); break;
    case IPPROTO_IGMP: r = disasm_igmp(list, p, s, paysize); break;
    case IPPROTO_TCP:  r = disasm_tcp( list, p, s, paysize); break;
    case IPPROTO_UDP:  r = disasm_udp( list, p, s, paysize); break;
    default: break;
    }
  }

  if (r < 0)
    return r;

  p += r;
  r = p - pktbuf;

  s = minval(hdrsize + paysize, size) - r;
  if (s > 0) {
    pkt_asm_list_add_val(list, PKT_ASM_FIELD_IP_DATA,
			 pkt_asm_val_create_binary(s, p));
    p += s;
    r += s;
  }

  return r;
}

static int disasm_icmp6(pkt_asm_list_t list, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct icmp6_hdr *icmp6hdr;

  if (size < sizeof(*icmp6hdr))
    return -1;
  icmp6hdr = (struct icmp6_hdr *)buffer;

  pkt_asm_list_add_val(list, PKT_ASM_FIELD_ICMPV6_TYPE,
		       pkt_asm_val_create_integer(icmp6hdr->icmp6_type));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_ICMPV6_CODE,
		       pkt_asm_val_create_integer(icmp6hdr->icmp6_code));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_ICMPV6_CHECKSUM,
		       pkt_asm_val_create_integer(ntohs(icmp6hdr->icmp6_cksum)));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_ICMPV6_DATA,
		       pkt_asm_val_create_integer(ntohl(icmp6hdr->icmp6_data32[0])));

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

static int disasm_ip6(pkt_asm_list_t list, char *buffer, int size)
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

  pkt_asm_list_add_val(list, PKT_ASM_FIELD_IPV6_VERSION,
		       pkt_asm_val_create_integer(ip6hdr->ip6_vfc >> 4));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_IPV6_FLOWID,
		       pkt_asm_val_create_integer(ntohl(ip6hdr->ip6_flow) & 0xffffff));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_IPV6_PAYLOAD_SIZE,
		       pkt_asm_val_create_integer(paysize));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_IPV6_HOP_LIMIT,
		       pkt_asm_val_create_integer(ip6hdr->ip6_hlim));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_IPV6_SRC_ADDR,
		       pkt_asm_val_create_ipv6addr(&ip6hdr->ip6_src));
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_IPV6_DST_ADDR,
		       pkt_asm_val_create_ipv6addr(&ip6hdr->ip6_dst));

  p = pktbuf + hdrsize;
  s = size   - hdrsize;

  nexthdr = ip6hdr->ip6_nxt;

  while (1) {
    pkt_asm_list_add_val(list, PKT_ASM_FIELD_IPV6_NEXT_HEADER,
			 pkt_asm_val_create_integer(nexthdr));
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
    pkt_asm_list_add_val(list, PKT_ASM_FIELD_IPV6_EXT_SIZE,
			 pkt_asm_val_create_integer(exthdrsize));
#ifndef IP6OPT_MINLEN
#define IP6OPT_MINLEN 2
#endif
    if (exthdrsize > IP6OPT_MINLEN) {
      pkt_asm_list_add_val(list, PKT_ASM_FIELD_IPV6_EXT_DATA,
			pkt_asm_val_create_binary(exthdrsize - IP6OPT_MINLEN,
						  p + IP6OPT_MINLEN));
    }
    p       += exthdrsize;
    s       -= exthdrsize;
    hdrsize += exthdrsize;
    paysize -= exthdrsize;
  }

  if (ip6fraghdr == NULL) {
    switch (nexthdr) {
    case IPPROTO_ICMPV6: r = disasm_icmp6(list, p, s, paysize); break;
    case IPPROTO_TCP:    r = disasm_tcp(  list, p, s, paysize); break;
    case IPPROTO_UDP:    r = disasm_udp(  list, p, s, paysize); break;
    default: break;
    }
  }

  if (r < 0)
    return r;

  p += r;
  r = p - pktbuf;

  s = minval(hdrsize + paysize, size) - r;
  if (s > 0) {
    pkt_asm_list_add_val(list, PKT_ASM_FIELD_IPV6_DATA,
			 pkt_asm_val_create_binary(s, p));
    p += s;
    r += s;
  }

  return r;
}

int pkt_disasm_ethernet(pkt_asm_list_t list, char *buffer, int size)
{
  char *p;
  int s, r = 0;
  struct ether_header ehdr;
  struct {
    pkt_uint16 tag;
    pkt_uint16 proto;
  } vlantag;
  int type;
  pkt_asm_val_t val;

  if (size < ETHER_HDR_LEN)
    return -1;
  memcpy(&ehdr, buffer, ETHER_HDR_LEN);

  val = pkt_asm_val_create_macaddr((struct ether_addr *)ehdr.ether_dhost);
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_ETHERNET_DST_ADDR, val);
  val = pkt_asm_val_create_macaddr((struct ether_addr *)ehdr.ether_shost);
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_ETHERNET_SRC_ADDR, val);
  pkt_asm_list_add_val(list, PKT_ASM_FIELD_ETHERNET_TYPE,
		       pkt_asm_val_create_integer(ntohs(ehdr.ether_type)));

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
    pkt_asm_list_add_val(list, PKT_ASM_FIELD_ETHERNET_VLAN_TAG,
			 pkt_asm_val_create_integer(ntohs(vlantag.tag)));
    pkt_asm_list_add_val(list, PKT_ASM_FIELD_ETHERNET_TYPE,
			 pkt_asm_val_create_integer(ntohs(vlantag.proto)));
    type = ntohs(vlantag.proto);
    p += sizeof(vlantag);
    s -= sizeof(vlantag);
  }

  switch (type) {
  case ETHERTYPE_ARP:  r = disasm_arp(list, p, s); break;
  case ETHERTYPE_IP:   r = disasm_ip( list, p, s); break;
  case ETHERTYPE_IPV6: r = disasm_ip6(list, p, s); break;
  default: break;
  }

  if (r < 0)
    return r;

  p += r;
  r = p - buffer;

  s = size - r;
  if (s > 0) {
    pkt_asm_list_add_val(list, PKT_ASM_FIELD_ETHERNET_DATA,
			 pkt_asm_val_create_binary(s, p));
    p += s;
    r += s;
  }

  return r;
}
