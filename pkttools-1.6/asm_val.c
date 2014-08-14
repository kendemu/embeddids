#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/in.h>

#include "asm_val.h"
#include "lib.h"

struct pkt_asm_val {
  pkt_asm_val_type_t type;
  union {
    int integer;
    struct ether_addr macaddr;
    struct in_addr ipaddr;
    struct in6_addr ipv6addr;
    char *string;
    struct {
      int size;
      int data_size;
      void *data;
    } binary;
  } value;
};

static pkt_asm_val_t pkt_asm_val_create(pkt_asm_val_type_t type)
{
  pkt_asm_val_t val;

  val = malloc(sizeof(*val));
  if (val == NULL)
    error_exit("Out of memory.\n");

  memset(val, 0, sizeof(*val));

  val->type = type;

  return val;
}

pkt_asm_val_t pkt_asm_val_create_integer(int integer)
{
  pkt_asm_val_t val;
  val = pkt_asm_val_create(PKT_ASM_VAL_TYPE_INTEGER);
  pkt_asm_val_set_value_integer(val, integer);
  return val;
}

pkt_asm_val_t pkt_asm_val_create_macaddr(struct ether_addr *macaddr)
{
  pkt_asm_val_t val;
  val = pkt_asm_val_create(PKT_ASM_VAL_TYPE_MACADDR);
  pkt_asm_val_set_value_macaddr(val, macaddr);
  return val;
}

pkt_asm_val_t pkt_asm_val_create_ipaddr(struct in_addr *ipaddr)
{
  pkt_asm_val_t val;
  val = pkt_asm_val_create(PKT_ASM_VAL_TYPE_IPADDR);
  pkt_asm_val_set_value_ipaddr(val, ipaddr);
  return val;
}

pkt_asm_val_t pkt_asm_val_create_ipv6addr(struct in6_addr *ipv6addr)
{
  pkt_asm_val_t val;
  val = pkt_asm_val_create(PKT_ASM_VAL_TYPE_IPV6ADDR);
  pkt_asm_val_set_value_ipv6addr(val, ipv6addr);
  return val;
}

pkt_asm_val_t pkt_asm_val_create_string(char *string)
{
  pkt_asm_val_t val;
  val = pkt_asm_val_create(PKT_ASM_VAL_TYPE_STRING);
  val->value.string = NULL;
  pkt_asm_val_set_value_string(val, string);
  return val;
}

pkt_asm_val_t pkt_asm_val_create_binary(int size, void *data)
{
  pkt_asm_val_t val;
  val = pkt_asm_val_create(PKT_ASM_VAL_TYPE_BINARY);
  val->value.binary.size = 0;
  val->value.binary.data_size = 0;
  val->value.binary.data = NULL;
  pkt_asm_val_set_value_binary(val, size, data);
  return val;
}

pkt_asm_val_t pkt_asm_val_destroy(pkt_asm_val_t val)
{
  if (val) {
    switch (val->type) {
    case PKT_ASM_VAL_TYPE_STRING:
      if (val->value.string) free(val->value.string);
      break;
    default:
      break;
    }
    free(val);
  }
  return NULL;
}

pkt_asm_val_type_t pkt_asm_val_get_type(pkt_asm_val_t val)
{
  return val->type;
}

int pkt_asm_val_get_value_integer(pkt_asm_val_t val)
{
  if (val->type != PKT_ASM_VAL_TYPE_INTEGER)
    return -1;
  return val->value.integer;
}

struct ether_addr *pkt_asm_val_get_value_macaddr(pkt_asm_val_t val)
{
  if (val->type != PKT_ASM_VAL_TYPE_MACADDR)
    return NULL;
  return &val->value.macaddr;
}

struct in_addr *pkt_asm_val_get_value_ipaddr(pkt_asm_val_t val)
{
  if (val->type != PKT_ASM_VAL_TYPE_IPADDR)
    return NULL;
  return &val->value.ipaddr;
}

struct in6_addr *pkt_asm_val_get_value_ipv6addr(pkt_asm_val_t val)
{
  if (val->type != PKT_ASM_VAL_TYPE_IPV6ADDR)
    return NULL;
  return &val->value.ipv6addr;
}

char *pkt_asm_val_get_value_string(pkt_asm_val_t val)
{
  if (val->type != PKT_ASM_VAL_TYPE_STRING)
    return NULL;
  return val->value.string;
}

int pkt_asm_val_get_value_binary_size(pkt_asm_val_t val)
{
  if (val->type != PKT_ASM_VAL_TYPE_BINARY)
    return -1;
  return val->value.binary.size;
}

void *pkt_asm_val_get_value_binary_data(pkt_asm_val_t val)
{
  if (val->type != PKT_ASM_VAL_TYPE_BINARY)
    return NULL;
  return val->value.binary.data;
}

int pkt_asm_val_set_value_integer(pkt_asm_val_t val, int integer)
{
  if (val->type != PKT_ASM_VAL_TYPE_INTEGER)
    return -1;
  val->value.integer = integer;
  return 0;
}

int pkt_asm_val_set_value_macaddr(pkt_asm_val_t val, struct ether_addr *macaddr)
{
  if (val->type != PKT_ASM_VAL_TYPE_MACADDR)
    return -1;
  memcpy(&val->value.macaddr, macaddr, ETHER_ADDR_LEN);
  return 0;
}

int pkt_asm_val_set_value_ipaddr(pkt_asm_val_t val, struct in_addr *ipaddr)
{
  if (val->type != PKT_ASM_VAL_TYPE_IPADDR)
    return -1;
  memcpy(&val->value.ipaddr, ipaddr, sizeof(*ipaddr));
  return 0;
}

int pkt_asm_val_set_value_ipv6addr(pkt_asm_val_t val, struct in6_addr *ipv6addr)
{
  if (val->type != PKT_ASM_VAL_TYPE_IPV6ADDR)
    return -1;
  memcpy(&val->value.ipv6addr, ipv6addr, sizeof(*ipv6addr));
  return 0;
}

int pkt_asm_val_set_value_string(pkt_asm_val_t val, char *string)
{
  if (val->type != PKT_ASM_VAL_TYPE_STRING)
    return -1;
  if (val->value.string)
    free(val->value.string);
  val->value.string = strdup(string);
  if (val->value.string == NULL)
    error_exit("Out of memory.\n");
  return 0;
}

int pkt_asm_val_set_value_binary(pkt_asm_val_t val, int size, void *data)
{
  int data_size;
  if (val->type != PKT_ASM_VAL_TYPE_BINARY)
    return -1;
  if (val->value.binary.data)
    free(val->value.binary.data);
  if (size > 0) {
    data_size = ((size / 16) + 2) * 16;
    val->value.binary.size = size;
    val->value.binary.data_size = data_size;
    val->value.binary.data = malloc(data_size);
    if (val->value.binary.data == NULL)
      error_exit("Out of memory.\n");
    memcpy(val->value.binary.data, data, size);
  } else {
    val->value.binary.size = 0;
    val->value.binary.data_size = 0;
    val->value.binary.data = NULL;
  }
  return 0;
}

int pkt_asm_val_add_value_binary(pkt_asm_val_t val, int size, void *data)
{
  int s, data_size;
  void *p;
  if (val->type != PKT_ASM_VAL_TYPE_BINARY)
    return -1;
  if (size > 0) {
    s = val->value.binary.size;
    if (size > val->value.binary.data_size - s) {
      p = val->value.binary.data;
      data_size = (((size + s) / 16) + 2) * 16;
      val->value.binary.data = malloc(data_size);
      if (val->value.binary.data == NULL)
	error_exit("Out of memory.\n");
      if (p) {
	memcpy(val->value.binary.data, p, s);
	free(p);
      }
    }
    val->value.binary.size = s + size;
    memcpy((char *)val->value.binary.data + s, data, size);
  }
  return 0;
}
