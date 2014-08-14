#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "asm_val.h"
#include "asm_field.h"
#include "asm_entry.h"
#include "asm_list.h"
#include "lib.h"

struct pkt_asm_list {
  pkt_asm_entry_t head;
  pkt_asm_entry_t *tail;
};

pkt_asm_list_t pkt_asm_list_create()
{
  pkt_asm_list_t list;

  list = malloc(sizeof(*list));
  if (list == NULL)
    error_exit("Out of memory.\n");

  memset(list, 0, sizeof(*list));

  list->head = NULL;
  list->tail = &list->head;

  return list;
}

pkt_asm_list_t pkt_asm_list_destroy(pkt_asm_list_t list)
{
  pkt_asm_val_t val;
  if (list) {
    while (list->head) {
      val = pkt_asm_list_del_val(list, PKT_ASM_FIELD_NONE);
      pkt_asm_val_destroy(val);
    }
    free(list);
  }
  return NULL;
}

pkt_asm_entry_t pkt_asm_list_get_head(pkt_asm_list_t list)
{
  return list->head;
}

int pkt_asm_list_add_val(pkt_asm_list_t list, pkt_asm_field_t field,
			 pkt_asm_val_t val)
{
  pkt_asm_entry_t entry;

  if (list == NULL)
    return -1;

  if ((field == PKT_ASM_FIELD_NONE) || (val == NULL))
    return -1;

  entry = pkt_asm_entry_create(field, val);

  entry->next = NULL;
  *(list->tail) = entry;
  list->tail = &entry->next;

  return 0;
}

pkt_asm_val_t pkt_asm_list_del_val(pkt_asm_list_t list,
				   pkt_asm_field_t field)
{
  pkt_asm_val_t val;
  pkt_asm_entry_t entry = NULL, *p;

  if (list == NULL)
    return NULL;

  for (p = &list->head; *p; p = &(*p)->next) {
    if ((field == PKT_ASM_FIELD_NONE) || ((*p)->field == field)) {
      entry = *p;
      if (list->tail == &entry->next) {
	list->tail = p;
      }
      *p = (*p)->next;
      entry->next = NULL;
      break;
    }
  }

  if (entry == NULL)
    return NULL;

  val = entry->val;
  entry->val = NULL;
  pkt_asm_entry_destroy(entry);

  return val;
}
