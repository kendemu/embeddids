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
#include "assemble.h"
#include "lib.h"

static int assemble_arp(pkt_asm_list_t list, char *buffer, int size)
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

  if (size < sizeof(arphdr))
    return -1;
  memcpy(&arphdr, buffer, sizeof(arphdr));

  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ARP_HARDWARE))) {
    arphdr.ar_hrd = htons(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ARP_PROTOCOL))) {
    arphdr.ar_pro = htons(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ARP_HARDWARE_SIZE))) {
    arphdr.ar_hln = pkt_asm_val_get_value_integer(val);
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ARP_PROTOCOL_SIZE))) {
    arphdr.ar_pln = pkt_asm_val_get_value_integer(val);
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ARP_OPERATION))) {
    arphdr.ar_op = htons(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }

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

  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ARP_SENDER_MACADDR))) {
    memcpy(arpdata.sender_macaddr.octet,
	   pkt_asm_val_get_value_macaddr(val), ETHER_ADDR_LEN);
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ARP_SENDER_IPADDR))) {
    arpdata.sender_ipaddr.s_addr =
      htonl(pkt_asm_val_get_value_ipaddr(val)->s_addr);
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ARP_TARGET_MACADDR))) {
    memcpy(arpdata.target_macaddr.octet,
	   pkt_asm_val_get_value_macaddr(val), ETHER_ADDR_LEN);
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ARP_TARGET_IPADDR))) {
    arpdata.target_ipaddr.s_addr =
      htonl(pkt_asm_val_get_value_ipaddr(val)->s_addr);
    pkt_asm_val_destroy(val);
  }

  memcpy(sip, &arpdata.sender_ipaddr.s_addr, sizeof(in_addr_t));
  memcpy(tip, &arpdata.target_ipaddr.s_addr, sizeof(in_addr_t));

  memcpy(buffer, &arphdr, sizeof(arphdr));

  size = p - buffer;

  return size;
}

static int assemble_icmp(pkt_asm_list_t list, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct icmp *icmphdr;
  pkt_asm_val_t val;

  if (size < sizeof(*icmphdr))
    return -1;
  icmphdr = (struct icmp *)buffer;

  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ICMP_TYPE))) {
    icmphdr->icmp_type = pkt_asm_val_get_value_integer(val);
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ICMP_CODE))) {
    icmphdr->icmp_code = pkt_asm_val_get_value_integer(val);
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ICMP_CHECKSUM))) {
    icmphdr->icmp_cksum = htons(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }

  s = sizeof(*icmphdr);
  p += s;
  r += s;

  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ICMP_DATA))) {
    s = minval(total_size, size) - r;
    if (s > 0) {
      s = minval(pkt_asm_val_get_value_binary_size(val), s);
      memcpy(p, pkt_asm_val_get_value_binary_data(val), s);
      p += s;
      r += s;
    }
    pkt_asm_val_destroy(val);
  }

  return r;
}

static int assemble_igmp(pkt_asm_list_t list, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct igmp *igmphdr;
  pkt_asm_val_t val;

  if (size < sizeof(*igmphdr))
    return -1;
  igmphdr = (struct igmp *)buffer;

  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IGMP_TYPE))) {
    igmphdr->igmp_type = pkt_asm_val_get_value_integer(val);
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IGMP_CODE))) {
    igmphdr->igmp_code = pkt_asm_val_get_value_integer(val);
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IGMP_CHECKSUM))) {
    igmphdr->igmp_cksum = htons(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IGMP_GROUP))) {
    igmphdr->igmp_group.s_addr =
      htonl(pkt_asm_val_get_value_ipaddr(val)->s_addr);
    pkt_asm_val_destroy(val);
  }

  s = sizeof(*igmphdr);
  p += s;
  r += s;

  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IGMP_DATA))) {
    s = minval(total_size, size) - r;
    if (s > 0) {
      s = minval(pkt_asm_val_get_value_binary_size(val), s);
      memcpy(p, pkt_asm_val_get_value_binary_data(val), s);
      p += s;
      r += s;
    }
    pkt_asm_val_destroy(val);
  }

  return r;
}

static int assemble_tcp(pkt_asm_list_t list, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct tcphdr *tcphdr;
  pkt_asm_val_t val;

  if (size < sizeof(*tcphdr))
    return -1;
  tcphdr = (struct tcphdr *)buffer;

  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_TCP_SRC_PORT))) {
    tcphdr->th_sport = htons(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_TCP_DST_PORT))) {
    tcphdr->th_dport = htons(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_TCP_SEQ_NUMBER))) {
    tcphdr->th_seq = htonl(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_TCP_ACK_NUMBER))) {
    tcphdr->th_ack = htonl(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_TCP_OFFSET))) {
    tcphdr->th_off = pkt_asm_val_get_value_integer(val) >> 2;
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_TCP_FLAGS))) {
    tcphdr->th_flags = pkt_asm_val_get_value_integer(val);
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_TCP_WINDOW))) {
    tcphdr->th_win = htons(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_TCP_CHECKSUM))) {
    tcphdr->th_sum = htons(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_TCP_URGENT))) {
    tcphdr->th_urp = htons(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }

  s = sizeof(*tcphdr);
  p += s;
  r += s;

  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_TCP_DATA))) {
    s = minval(total_size, size) - r;
    if (s > 0) {
      s = minval(pkt_asm_val_get_value_binary_size(val), s);
      memcpy(p, pkt_asm_val_get_value_binary_data(val), s);
      p += s;
      r += s;
    }
    pkt_asm_val_destroy(val);
  }

  return r;
}

static int assemble_udp(pkt_asm_list_t list, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct udphdr *udphdr;
  pkt_asm_val_t val;

  if (size < sizeof(*udphdr))
    return -1;
  udphdr = (struct udphdr *)buffer;

  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_UDP_SRC_PORT))) {
    udphdr->uh_sport = htons(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_UDP_DST_PORT))) {
    udphdr->uh_dport = htons(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_UDP_SIZE))) {
    udphdr->uh_ulen = htons(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_UDP_CHECKSUM))) {
    udphdr->uh_sum = htons(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }

  s = sizeof(*udphdr);
  p += s;
  r += s;

  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_UDP_DATA))) {
    s = minval(total_size, size) - r;
    if (s > 0) {
      s = minval(pkt_asm_val_get_value_binary_size(val), s);
      memcpy(p, pkt_asm_val_get_value_binary_data(val), s);
      p += s;
      r += s;
    }
    pkt_asm_val_destroy(val);
  }

  return r;
}

static int assemble_ip(pkt_asm_list_t list, char *buffer, int size)
{
  static char *pktbuf = NULL;
  static int bufsize = 0;
  char *p;
  int s, r = 0;
  struct ip *iphdr;
  int hdrsize, paysize;
  pkt_asm_val_t val;

  pktbuf = pkt_alloc_buffer(pktbuf, &bufsize, size);

  if (size < sizeof(*iphdr))
    return -1;

  memcpy(pktbuf, buffer, size);
  iphdr = (struct ip *)pktbuf;

  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IP_VERSION))) {
    iphdr->ip_v = pkt_asm_val_get_value_integer(val);
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IP_HEADER_SIZE))) {
    iphdr->ip_hl = pkt_asm_val_get_value_integer(val) >> 2;
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IP_TOS))) {
    iphdr->ip_tos = pkt_asm_val_get_value_integer(val);
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IP_TOTAL_SIZE))) {
    iphdr->ip_len = htons(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IP_ID))) {
    iphdr->ip_id = htons(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IP_FRAGMENT))) {
    iphdr->ip_off = htons(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IP_TTL))) {
    iphdr->ip_ttl = pkt_asm_val_get_value_integer(val);
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IP_PROTOCOL))) {
    iphdr->ip_p = pkt_asm_val_get_value_integer(val);
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IP_CHECKSUM))) {
    iphdr->ip_sum = htons(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IP_SRC_ADDR))) {
    iphdr->ip_src.s_addr = htonl(pkt_asm_val_get_value_ipaddr(val)->s_addr);
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IP_DST_ADDR))) {
    iphdr->ip_dst.s_addr = htonl(pkt_asm_val_get_value_ipaddr(val)->s_addr);
    pkt_asm_val_destroy(val);
  }

  hdrsize = iphdr->ip_hl << 2;
  paysize = ntohs(iphdr->ip_len) - hdrsize;

  p = pktbuf + hdrsize;
  s = size   - hdrsize;

  if ((ntohs(iphdr->ip_off) & (IP_MF|IP_OFFMASK)) == 0) {
    switch (iphdr->ip_p) {
    case IPPROTO_ICMP: r = assemble_icmp(list, p, s, paysize); break;
    case IPPROTO_IGMP: r = assemble_igmp(list, p, s, paysize); break;
    case IPPROTO_TCP:  r = assemble_tcp( list, p, s, paysize); break;
    case IPPROTO_UDP:  r = assemble_udp( list, p, s, paysize); break;
    default: break;
    }
  }

  if (r < 0)
    return r;

  p += r;
  r = p - pktbuf;

  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IP_DATA))) {
    s = minval(hdrsize + paysize, size) - r;
    if (s > 0) {
      s = minval(pkt_asm_val_get_value_binary_size(val), s);
      memcpy(p, pkt_asm_val_get_value_binary_data(val), s);
      p += s;
      r += s;
    }
    pkt_asm_val_destroy(val);
  }

  memcpy(buffer, pktbuf, r);

  return r;
}

static int assemble_icmp6(pkt_asm_list_t list, char *buffer, int size, int total_size)
{
  char *p = buffer;
  int s, r = 0;
  struct icmp6_hdr *icmp6hdr;
  pkt_asm_val_t val;

  if (size < sizeof(*icmp6hdr))
    return -1;
  icmp6hdr = (struct icmp6_hdr *)buffer;

  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ICMPV6_TYPE))) {
    icmp6hdr->icmp6_type = pkt_asm_val_get_value_integer(val);
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ICMPV6_CODE))) {
    icmp6hdr->icmp6_code = pkt_asm_val_get_value_integer(val);
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ICMPV6_CHECKSUM))) {
    icmp6hdr->icmp6_cksum = htons(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ICMPV6_DATA))) {
    icmp6hdr->icmp6_data32[0] = htonl(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }

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

static int assemble_ip6(pkt_asm_list_t list, char *buffer, int size)
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
  pkt_asm_val_t val, val2;
  int copy_size;

  pktbuf = pkt_alloc_buffer(pktbuf, &bufsize, size);

  if (size < sizeof(*ip6hdr))
    return -1;

  memcpy(pktbuf, buffer, size);
  ip6hdr = (struct ip6_hdr *)pktbuf;

  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IPV6_VERSION))) {
    ip6hdr->ip6_vfc &= ~0xf0;
    ip6hdr->ip6_vfc |= pkt_asm_val_get_value_integer(val) << 4;
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IPV6_FLOWID))) {
    ip6hdr->ip6_flow = htonl(ntohl(ip6hdr->ip6_flow) & ~0xffffff);
    ip6hdr->ip6_flow |= htonl(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IPV6_PAYLOAD_SIZE))) {
    ip6hdr->ip6_plen = htons(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IPV6_HOP_LIMIT))) {
    ip6hdr->ip6_hlim = pkt_asm_val_get_value_integer(val);
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IPV6_SRC_ADDR))) {
    memcpy(&ip6hdr->ip6_src, pkt_asm_val_get_value_ipv6addr(val),
	   sizeof(struct in6_addr));
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IPV6_DST_ADDR))) {
    memcpy(&ip6hdr->ip6_dst, pkt_asm_val_get_value_ipv6addr(val),
	   sizeof(struct in6_addr));
    pkt_asm_val_destroy(val);
  }
  val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IPV6_NEXT_HEADER);
  if (val) {
    ip6hdr->ip6_nxt = pkt_asm_val_get_value_integer(val);
    pkt_asm_val_destroy(val);
  }

  hdrsize = sizeof(struct ip6_hdr);
  paysize = ntohs(ip6hdr->ip6_plen);

  p = pktbuf + hdrsize;
  s = size   - hdrsize;

  nexthdr = ip6hdr->ip6_nxt;

  while (1) {
    val  = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IPV6_NEXT_HEADER);
    val2 = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IPV6_EXT_SIZE);
    exthdrsize = 0;
    switch (nexthdr) {
    case IPPROTO_HOPOPTS:
    case IPPROTO_DSTOPTS:
      if (s < sizeof(*ip6exthdr))
	return -1;
      ip6exthdr = (struct ip6_ext *)p;
      if (val)
	ip6exthdr->ip6e_nxt = pkt_asm_val_get_value_integer(val);
      if (val2)
	ip6exthdr->ip6e_len = (pkt_asm_val_get_value_integer(val2) >> 3) - 1;
      nexthdr = ip6exthdr->ip6e_nxt;
      exthdrsize = (ip6exthdr->ip6e_len + 1) << 3;
      break;
    case IPPROTO_ROUTING:
      if (s < sizeof(*ip6rthdr))
	return -1;
      ip6rthdr = (struct ip6_rthdr *)p;
      if (val)
	ip6rthdr->ip6r_nxt = pkt_asm_val_get_value_integer(val);
      if (val2)
	ip6rthdr->ip6r_len = (pkt_asm_val_get_value_integer(val2) >> 3) - 1;
      nexthdr = ip6rthdr->ip6r_nxt;
      exthdrsize = (ip6rthdr->ip6r_len + 1) << 3;
      break;
    case IPPROTO_FRAGMENT:
      if (s < sizeof(*ip6fraghdr))
	return -1;
      ip6fraghdr = (struct ip6_frag *)p;
      if (val)
	ip6fraghdr->ip6f_nxt = pkt_asm_val_get_value_integer(val);
      nexthdr = ip6fraghdr->ip6f_nxt;
      exthdrsize = sizeof(*ip6fraghdr);
      break;
    case IPPROTO_NONE:
    default:
      break;
    }
    if (val)  pkt_asm_val_destroy(val);
    if (val2) pkt_asm_val_destroy(val2);
    if (exthdrsize == 0)
      break;
    if (s < exthdrsize)
      return -1;
    val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IPV6_EXT_DATA);
    if (val) {
#ifndef IP6OPT_MINLEN
#define IP6OPT_MINLEN 2
#endif
      copy_size = minval(pkt_asm_val_get_value_binary_size(val),
			 exthdrsize - IP6OPT_MINLEN);
      memcpy(p + IP6OPT_MINLEN, pkt_asm_val_get_value_binary_data(val),
	     copy_size);
      pkt_asm_val_destroy(val);
    }
    p       += exthdrsize;
    s       -= exthdrsize;
    hdrsize += exthdrsize;
    paysize -= exthdrsize;
  }

  if (ip6fraghdr == NULL) {
    switch (nexthdr) {
    case IPPROTO_ICMPV6: r = assemble_icmp6(list, p, s, paysize); break;
    case IPPROTO_TCP:    r = assemble_tcp(  list, p, s, paysize); break;
    case IPPROTO_UDP:    r = assemble_udp(  list, p, s, paysize); break;
    default: break;
    }
  }

  if (r < 0)
    return r;

  p += r;
  r = p - pktbuf;

  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_IPV6_DATA))) {
    s = minval(hdrsize + paysize, size) - r;
    if (s > 0) {
      s = minval(pkt_asm_val_get_value_binary_size(val), s);
      memcpy(p, pkt_asm_val_get_value_binary_data(val), s);
      p += s;
      r += s;
    }
    pkt_asm_val_destroy(val);
  }

  memcpy(buffer, pktbuf, r);

  return r;
}

int pkt_assemble_ethernet(pkt_asm_list_t list, char *buffer, int size)
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

  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ETHERNET_DST_ADDR))) {
    memcpy(ehdr.ether_dhost, pkt_asm_val_get_value_macaddr(val),
	   ETHER_ADDR_LEN);
    pkt_asm_val_destroy(val);
  }
  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ETHERNET_SRC_ADDR))) {
    memcpy(ehdr.ether_shost, pkt_asm_val_get_value_macaddr(val),
	   ETHER_ADDR_LEN);
    pkt_asm_val_destroy(val);
  }
  val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ETHERNET_TYPE);
  if (val) {
    ehdr.ether_type = htons(pkt_asm_val_get_value_integer(val));
    pkt_asm_val_destroy(val);
  }

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
    val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ETHERNET_VLAN_TAG);
    if (val) {
      vlantag.tag = htons(pkt_asm_val_get_value_integer(val));
      pkt_asm_val_destroy(val);
    }
    val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ETHERNET_TYPE);
    if (val) {
      vlantag.proto = htons(pkt_asm_val_get_value_integer(val));
      pkt_asm_val_destroy(val);
    }
    memcpy(p, &vlantag, sizeof(vlantag));
    type = ntohs(vlantag.proto);
    p += sizeof(vlantag);
    s -= sizeof(vlantag);
  }

  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ETHERNET_TYPE))) {
    type = pkt_asm_val_get_value_integer(val);
    pkt_asm_val_destroy(val);
  }

  ehdr.ether_type = htons(type);

  switch (type) {
  case ETHERTYPE_ARP:  r = assemble_arp(list, p, s); break;
  case ETHERTYPE_IP:   r = assemble_ip( list, p, s); break;
  case ETHERTYPE_IPV6: r = assemble_ip6(list, p, s); break;
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

  while ((val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_ETHERNET_DATA))) {
    s = size - r;
    if (s > 0) {
      s = minval(pkt_asm_val_get_value_binary_size(val), s);
      memcpy(p, pkt_asm_val_get_value_binary_data(val), s);
      p += s;
      r += s;
    }
    pkt_asm_val_destroy(val);
  }

  return r;
}
