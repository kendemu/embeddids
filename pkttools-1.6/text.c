#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#ifdef __linux__
#include <netinet/ether.h>
#endif
#include <arpa/inet.h>

#include "asm_val.h"
#include "asm_field.h"
#include "asm_entry.h"
#include "asm_list.h"
#include "text.h"
#include "lib.h"

#define COLUMN 16

static int isterminator(int c)
{
  return ((c == EOF) || (c == '\r') || (c == '\n')) ? 1 : 0;
}

static int getkey(FILE *fp, char *buffer, int size)
{
  int c, i = 0;

  while ((c = fgetc(fp)) != EOF) {
    if ((i >= size - 1) || (c == EOF) || (c == ':') || isspace(c))
      break;
    buffer[i++] = c;
  }
  buffer[i] = '\0';

  return c;
}

static int skip_line(FILE *fp)
{
  int c;
  while ((c = fgetc(fp)) != EOF) {
    if (isterminator(c))
      break;
  }
  return c;
}

static int read_num(FILE *fp, int *nump)
{
  int c, n, num = -1;
  while ((c = fgetc(fp)) != EOF) {
    if (num < 0) {
      if (isspace(c) && !isterminator(c))
	continue;
      if (!isdigit(c))
	break;
      num = 0;
    } else if (!isdigit(c)) {
      break;
    }
    n = c - '0';
    num = num * 10 + n;
  }
  if (nump) *nump = num;
  return c;
}

static int read_hex(FILE *fp, int *nump)
{
  int c, n, num = -1;
  while ((c = fgetc(fp)) != EOF) {
    if (num < 0) {
      if (isspace(c) && !isterminator(c))
	continue;
      if (!isxdigit(c))
	break;
      num = 0;
    } else if (!isxdigit(c)) {
      break;
    }
    if (isdigit(c))
      n = c - '0';
    else if ((c >= 'a') && (c <= 'f'))
      n = c - 'a' + 10;
    else
      n = c - 'A' + 10;
    num = num * 16 + n;
  }
  if (nump) *nump = num;
  return c;
}

static int read_str(FILE *fp, char *buffer, int size)
{
  int c = EOF;
  char *p = buffer;
  int start = 0;

  while (size > 1) {
    c = fgetc(fp);
    if (isterminator(c))
      break;
    if (!start) {
      if (isspace(c))
	continue;
      start++;
    } else {
      if (isspace(c))
	break;
    }
    *(p++) = c;
    size--;
  }
  *p = '\0';
  return c;
}

static int read_line(FILE *fp, char *buffer, int size)
{
  int c = EOF;
  char *p = buffer;
  int start = 0;

  while (size > 1) {
    c = fgetc(fp);
    if (isterminator(c))
      break;
    if (!start) {
      if (isspace(c))
	continue;
      start++;
    }
    *(p++) = c;
    size--;
  }
  *p = '\0';
  return c;
}

int pkt_text_read(FILE *fp, char *buffer, int size,
		  int *capsizep, int *origsizep, struct timeval *tp,
		  pkt_asm_list_t list)
{
  char inbuf[32];
  int i = 0, c, n, capsize, origsize;
  struct timeval t;
  pkt_asm_field_t field;

  capsize = origsize = -1;
  t.tv_sec = t.tv_usec = 0;

  while (1) {
    c = getkey(fp, inbuf, sizeof(inbuf));
    if (c == EOF)
      return -1;
    if (!isterminator(c))
      c = skip_line(fp);
    if (!strcmp(inbuf, "--")) {
      if (c == EOF)
	return -1;
      break;
    }
  }

  while (1) {
    c = getkey(fp, inbuf, sizeof(inbuf));

    if (!strcmp(inbuf, "==")) {
      if (!isterminator(c))
	c = skip_line(fp);
      break;
    }

    if (c == EOF)
      return -1;

    if (!strcmp(inbuf, "TIME")) {
      c = read_num(fp, &n);
      if (n >= 0) t.tv_sec = n;
      if (c == '.') {
	if (n < 0) t.tv_sec = 0;
	c = read_num(fp, &n);
	if (n >= 0) t.tv_usec = n;
	else t.tv_usec = 0;
      } else {
	if (n >= 0)
	  t.tv_usec = 0;
      }
      if (!isterminator(c))
	c = skip_line(fp);
      if (c == EOF)
	return -1;
      continue;
    }

    if (!strcmp(inbuf, "SIZE")) {
      c = read_num(fp, &n);
      if (n >= 0) capsize = n;
      if (c == '/') {
	if (n < 0) capsize = 0;
	c = read_num(fp, &n);
	if (n >= 0) origsize = n;
	else origsize = 0;
      } else {
	if (n >= 0)
	  origsize = -1;
      }
      if (!isterminator(c))
	c = skip_line(fp);
      if (c == EOF)
	return -1;
      continue;
    }

    field = pkt_asm_field_search_field_from_key(inbuf);
    if (field != PKT_ASM_FIELD_NONE) {
      pkt_asm_list_read(list, field, fp);
      continue;
    }

    if (!isxdigit(inbuf[0])) {
      if (!isterminator(c))
	c = skip_line(fp);
      if (c == EOF)
	return -1;
      continue;
    }

    if (isspace(c)) {
      if (i < size)
	buffer[i] = strtoul(inbuf, NULL, 16);
      else
	error_exit("Out of buffer.\n");
      i++;
    }
    if (isterminator(c)) {
      if (c == EOF)
	return -1;
      continue;
    }
    while (1) {
      c = read_hex(fp, &n);
      if (n >= 0) {
	if (i < size)
	  buffer[i] = n;
	else
	  error_exit("Out of buffer.\n");
	i++;
      }
      if ((n < 0) || !isspace(c) || isterminator(c)) {
	if (!isterminator(c))
	  c = skip_line(fp);
	if (c == EOF)
	  return -1;
	break;
      }
    }
  }

  if (capsize < 0) {
    capsize = i;
  } else if (capsize > i) {
    memset(&buffer[i], 0, capsize - i);
  }
  if (origsize < 0)
    origsize = capsize;

  if (capsize >= 0) {
    if (capsizep ) *capsizep  = capsize;
    if (origsizep) *origsizep = origsize;
    if (tp) {
      tp->tv_sec  = t.tv_sec;
      tp->tv_usec = t.tv_usec;
    }
  }

  return capsize;
}

int pkt_text_write(FILE *fp, char *buffer,
		   int capsize, int origsize, struct timeval *tp,
		   pkt_asm_list_t list)
{
  char text[COLUMN * 2];
  char *textp = NULL;
  unsigned char c;
  struct timeval zero;
  int i, size;
  static int count = 0;

  if (origsize < 0)
    origsize = capsize;

  zero.tv_sec = zero.tv_usec = 0;
  if (tp == NULL)
    tp = &zero;

  count++;
  fprintf(fp, "-- %d --\n", count);
  fprintf(fp, "TIME: %d.%06d %s",
	  (int)tp->tv_sec, (int)tp->tv_usec, ctime(&tp->tv_sec));
  fprintf(fp, "SIZE: %d/%d\n", capsize, origsize);

  size = ((capsize + COLUMN - 1) / COLUMN) * COLUMN;
  for (i = 0; i < size; i++) {
    if ((i % COLUMN) == 0) {
      textp = text;
      fprintf(fp, "%06X:", i);
    }

    if ((i % 4) == 0)
      fprintf(fp, " ");

    if (i < capsize) {
      c = buffer[i];
      fprintf(fp, "%02X ", c);
    } else {
      c = ' ';
      fprintf(fp, "   ");
    }

    if ((i % 8) == 0) *(textp++) = ' ';
    *(textp++) = isprint(c) ? c : '.';
    *textp = '\0';

    if ((i % COLUMN) == (COLUMN - 1))
      fprintf(fp, ":%s\n", text);
  }

  pkt_asm_list_write(list, fp);

  fprintf(fp, "==\n");
  fflush(fp);

  return 0;
}

typedef enum {
  OPERATOR_NONE,
  OPERATOR_EQ,
  OPERATOR_NE,
  OPERATOR_LE,
  OPERATOR_GE,
  OPERATOR_LT,
  OPERATOR_GT,
  OPERATOR_ASSIGN,
} operator_t;

static struct {
  operator_t op;
  char *mark;
} operators[] = {
  { OPERATOR_EQ,     "==" },
  { OPERATOR_NE,     "!=" },
  { OPERATOR_LE,     "<=" },
  { OPERATOR_GE,     ">=" },
  { OPERATOR_LT,     "<"  },
  { OPERATOR_GT,     ">"  },
  { OPERATOR_ASSIGN, "="  },
  { OPERATOR_NONE, NULL }
};

static operator_t search_operator(char *str, char **value)
{
  int i, len, length;
  char *p;

  length = strlen(str);

  for (p = str; p < str + length; p++) {
    for (i = 0; operators[i].op != OPERATOR_NONE; i++) {
      len = strlen(operators[i].mark);
      if ((str + length) - p < len)
	continue;
      if (!memcmp(p, operators[i].mark, len)) {
	if (value) {
	  memset(p, '\0', len);
	  *value = p + len;
	}
	return operators[i].op;
      }
    }
  }

  return OPERATOR_NONE;
}

static pkt_asm_val_t pkt_asm_list_read_value(pkt_asm_val_type_t type,
					     char *value)
{
  pkt_asm_val_t val = NULL;
  struct ether_addr *macaddr;
  struct in_addr ipaddr;
  struct in6_addr ipv6addr;
  char *p, *next;
  unsigned char c;

  switch (type) {
  case PKT_ASM_VAL_TYPE_INTEGER:
    val = pkt_asm_val_create_integer(strtoul(value, NULL, 0));
    break;
  case PKT_ASM_VAL_TYPE_MACADDR:
    macaddr = ether_aton(value);
    if (macaddr == NULL)
      return NULL;
    val = pkt_asm_val_create_macaddr(macaddr);
    break;
  case PKT_ASM_VAL_TYPE_IPADDR:
    if (inet_pton(AF_INET, value, &ipaddr) < 0)
      return NULL;
    ipaddr.s_addr = ntohl(ipaddr.s_addr);
    val = pkt_asm_val_create_ipaddr(&ipaddr);
    break;
  case PKT_ASM_VAL_TYPE_IPV6ADDR:
    if (inet_pton(AF_INET6, value, &ipv6addr) < 0)
      return NULL;
    val = pkt_asm_val_create_ipv6addr(&ipv6addr);
    break;
  case PKT_ASM_VAL_TYPE_STRING:
    val = pkt_asm_val_create_string(value);
    break;
  case PKT_ASM_VAL_TYPE_BINARY:
    val = NULL;
    for (p = value; *p; p = next) {
      c = strtoul(p, &next, 16);
      if (p == next)
	break;
      if (val == NULL)
	val = pkt_asm_val_create_binary(1, &c);
      else
	pkt_asm_val_add_value_binary(val, 1, &c);
    }
    break;
  case PKT_ASM_VAL_TYPE_NONE:
  default:
    return NULL;
  }

  return val;
}

int pkt_asm_list_read(pkt_asm_list_t list, pkt_asm_field_t field, FILE *fp)
{
  char buffer[256];
  int c;
  pkt_asm_val_t val;
  pkt_asm_val_type_t type;

  type = pkt_asm_field_get_type(field);
  if (type == PKT_ASM_VAL_TYPE_NONE) {
    skip_line(fp);
    return -1;
  }

  switch (type) {
  case PKT_ASM_VAL_TYPE_BINARY:
    c = read_line(fp, buffer, sizeof(buffer));
    break;
  default:
    c = read_str(fp, buffer, sizeof(buffer));
    if (!isterminator(c))
      skip_line(fp);
    break;
  }

  if (list == NULL)
    return -1;

  val = pkt_asm_list_read_value(type, buffer);
  if (val) pkt_asm_list_add_val(list, field, val);

  return 0;
}

int pkt_asm_list_write(pkt_asm_list_t list, FILE *fp)
{
  pkt_asm_entry_t entry;
  char *key;
  pkt_asm_val_t val;
  struct ether_addr *macaddr;
  struct in_addr ipaddr;
  char ipv6addrs[INET6_ADDRSTRLEN];
  int n, i, size;
  char *tab, *data;

  if (list == NULL)
    return -1;

  for (entry = pkt_asm_list_get_head(list); entry; entry = entry->next) {
    key = pkt_asm_field_get_key(entry->field);
    val = entry->val;
    n = (strlen(key) + 1) / 8;
    tab = &("\t\t\t"[(n > 2) ? 2 : n]);
    switch (pkt_asm_val_get_type(val)) {
    case PKT_ASM_VAL_TYPE_INTEGER:
      fprintf(fp, "%s:%s0x%x\n", key, tab, pkt_asm_val_get_value_integer(val));
      break;
    case PKT_ASM_VAL_TYPE_MACADDR:
      macaddr = pkt_asm_val_get_value_macaddr(val);
      fprintf(fp, "%s:%s%s\n", key, tab, ether_ntoa(macaddr));
      break;
    case PKT_ASM_VAL_TYPE_IPADDR:
      ipaddr.s_addr = htonl(pkt_asm_val_get_value_ipaddr(val)->s_addr);
      fprintf(fp, "%s:%s%s\n", key, tab, inet_ntoa(ipaddr));
      break;
    case PKT_ASM_VAL_TYPE_IPV6ADDR:
      if (inet_ntop(AF_INET6, pkt_asm_val_get_value_ipv6addr(val),
		    ipv6addrs, sizeof(ipv6addrs)) == NULL)
	break;
      fprintf(fp, "%s:%s%s\n", key, tab, ipv6addrs);
      break;
    case PKT_ASM_VAL_TYPE_STRING:
      fprintf(fp, "%s:%s%s\n", key, tab, pkt_asm_val_get_value_string(val));
      break;
    case PKT_ASM_VAL_TYPE_BINARY:
      size = pkt_asm_val_get_value_binary_size(val);
      data = pkt_asm_val_get_value_binary_data(val);
      for (i = 0; i < size; i++) {
	if ((i % 16) == 0) {
	  if (i > 0)
	    fprintf(fp, "\n");
	  fprintf(fp, "%s:%s", key, tab);
	} else {
	  if ((i % 4) == 0)
	    fprintf(fp, " ");
	  fprintf(fp, " ");
	}
	fprintf(fp, "%02X", ((unsigned char *)data)[i]);
      }
      fprintf(fp, "\n");
      break;
    case PKT_ASM_VAL_TYPE_NONE:
    default:
      break;
    }
  }

  return 0;
}

int pkt_asm_list_read_args(pkt_asm_list_t list, int argc, char *argv[])
{
  char buffer[256];
  char *value;
  int i;
  pkt_asm_field_t field;
  pkt_asm_val_t val;
  pkt_asm_val_type_t type;

  if (list == NULL)
    return -1;

  for (i = 0; i < argc; i++) {
    if (strlen(argv[i]) + 1 > sizeof(buffer))
      continue;

    strcpy(buffer, argv[i]);

    if (search_operator(buffer, &value) != OPERATOR_ASSIGN)
      continue;

    field = pkt_asm_field_search_field_from_key(buffer);
    if (field == PKT_ASM_FIELD_NONE)
      continue;

    type = pkt_asm_field_get_type(field);
    if (type == PKT_ASM_VAL_TYPE_NONE)
      continue;

    val = pkt_asm_list_read_value(type, value);
    if (val) pkt_asm_list_add_val(list, field, val);
  }

  return 0;
}

static int value_check(operator_t operator, int diff)
{
  switch (operator) {
  case OPERATOR_EQ: if (diff == 0) return 1; break;
  case OPERATOR_NE: if (diff != 0) return 1; break;
  case OPERATOR_LE: if (diff <= 0) return 1; break;
  case OPERATOR_GE: if (diff >= 0) return 1; break;
  case OPERATOR_LT: if (diff <  0) return 1; break;
  case OPERATOR_GT: if (diff >  0) return 1; break;
  default: break;
  }
  return 0;
}

static int value_intcheck(operator_t operator,
			  unsigned int integer1, unsigned int integer2)
{
  return value_check(operator, integer1 - integer2);
}

static int value_memcheck(operator_t operator, void *p1, void *p2, int size)
{
  return value_check(operator, memcmp(p1, p2, size));
}

static int value_strcheck(operator_t operator, char *s1, char *s2)
{
  return value_check(operator, strcmp(s1, s2));
}

int pkt_asm_list_filter_args(pkt_asm_list_t list, int argc, char *argv[])
{
  char buffer[256];
  char *value;
  int i, r = -1;
  pkt_asm_field_t field;
  pkt_asm_val_t val1, val2;
  pkt_asm_val_type_t type;
  operator_t operator;
  int integer1, integer2;
  struct ether_addr *macaddr1, *macaddr2;
  struct in_addr *ipaddr1, *ipaddr2;
  struct in6_addr *ipv6addr1, *ipv6addr2;
  char *string1, *string2;

  for (i = 0; i < argc; i++) {
    if (strlen(argv[i]) + 1 > sizeof(buffer))
      continue;

    strcpy(buffer, argv[i]);

    operator = search_operator(buffer, &value);
    if ((operator == OPERATOR_NONE) || (operator == OPERATOR_ASSIGN))
      continue;

    field = pkt_asm_field_search_field_from_key(buffer);
    if (field == PKT_ASM_FIELD_NONE)
      continue;

    type = pkt_asm_field_get_type(field);
    if (type == PKT_ASM_VAL_TYPE_NONE)
      continue;

    val2 = pkt_asm_list_read_value(type, value);
    if (val2 == NULL)
      continue;

    if (r < 0)
      r = 0;

    if (list == NULL)
      break;

    val1 = pkt_asm_list_del_val(list, field);
    if (val1 == NULL) {
      pkt_asm_val_destroy(val2);
      continue;
    }

    switch (type) {
    case PKT_ASM_VAL_TYPE_INTEGER:
      integer1 = pkt_asm_val_get_value_integer(val1);
      integer2 = pkt_asm_val_get_value_integer(val2);
      r = value_intcheck(operator, integer1, integer2);
      break;
    case PKT_ASM_VAL_TYPE_MACADDR:
      macaddr1 = pkt_asm_val_get_value_macaddr(val1);
      macaddr2 = pkt_asm_val_get_value_macaddr(val2);
      r = value_memcheck(operator, macaddr1, macaddr2, ETHER_ADDR_LEN);
      break;
    case PKT_ASM_VAL_TYPE_IPADDR:
      ipaddr1 = pkt_asm_val_get_value_ipaddr(val1);
      ipaddr2 = pkt_asm_val_get_value_ipaddr(val2);
      r = value_intcheck(operator, ipaddr1->s_addr, ipaddr2->s_addr);
      break;
    case PKT_ASM_VAL_TYPE_IPV6ADDR:
      ipv6addr1 = pkt_asm_val_get_value_ipv6addr(val1);
      ipv6addr2 = pkt_asm_val_get_value_ipv6addr(val2);
      r = value_memcheck(operator, ipv6addr1, ipv6addr2,
			 sizeof(struct in6_addr));
      break;
    case PKT_ASM_VAL_TYPE_STRING:
      string1 = pkt_asm_val_get_value_string(val1);
      string2 = pkt_asm_val_get_value_string(val2);
      r = value_strcheck(operator, string1, string2);
      break;
    case PKT_ASM_VAL_TYPE_NONE:
    default:
      break;
    }

    pkt_asm_val_destroy(val1);
    pkt_asm_val_destroy(val2);

    if (r)
      break;
  }

  return r;
}
