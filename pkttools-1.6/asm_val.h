#ifndef _PKTTOOLS_ASM_VAL_H_INCLUDED_
#define _PKTTOOLS_ASM_VAL_H_INCLUDED_

typedef enum {
  PKT_ASM_VAL_TYPE_NONE,
  PKT_ASM_VAL_TYPE_INTEGER,
  PKT_ASM_VAL_TYPE_MACADDR,
  PKT_ASM_VAL_TYPE_IPADDR,
  PKT_ASM_VAL_TYPE_IPV6ADDR,
  PKT_ASM_VAL_TYPE_STRING,
  PKT_ASM_VAL_TYPE_BINARY,
} pkt_asm_val_type_t;

typedef struct pkt_asm_val *pkt_asm_val_t;

struct ether_addr;
struct in_addr;
struct in6_addr;

pkt_asm_val_t pkt_asm_val_create_integer(int integer);
pkt_asm_val_t pkt_asm_val_create_macaddr(struct ether_addr *macaddr);
pkt_asm_val_t pkt_asm_val_create_ipaddr(struct in_addr *ipaddr);
pkt_asm_val_t pkt_asm_val_create_ipv6addr(struct in6_addr *ipv6addr);
pkt_asm_val_t pkt_asm_val_create_string(char *string);
pkt_asm_val_t pkt_asm_val_create_binary(int size, void *data);
pkt_asm_val_t pkt_asm_val_destroy(pkt_asm_val_t val);

pkt_asm_val_type_t pkt_asm_val_get_type(pkt_asm_val_t val);

int pkt_asm_val_get_value_integer(pkt_asm_val_t val);
struct ether_addr *pkt_asm_val_get_value_macaddr(pkt_asm_val_t val);
struct in_addr *pkt_asm_val_get_value_ipaddr(pkt_asm_val_t val);
struct in6_addr *pkt_asm_val_get_value_ipv6addr(pkt_asm_val_t val);
char *pkt_asm_val_get_value_string(pkt_asm_val_t val);
int pkt_asm_val_get_value_binary_size(pkt_asm_val_t val);
void *pkt_asm_val_get_value_binary_data(pkt_asm_val_t val);

int pkt_asm_val_set_value_integer(pkt_asm_val_t val, int integer);
int pkt_asm_val_set_value_macaddr(pkt_asm_val_t val, struct ether_addr *macaddr);
int pkt_asm_val_set_value_ipaddr(pkt_asm_val_t val, struct in_addr *ipaddr);
int pkt_asm_val_set_value_ipv6addr(pkt_asm_val_t val, struct in6_addr *ipv6addr);
int pkt_asm_val_set_value_string(pkt_asm_val_t val, char *string);
int pkt_asm_val_set_value_binary(pkt_asm_val_t val, int size, void *data);

int pkt_asm_val_add_value_binary(pkt_asm_val_t val, int size, void *data);

#endif
