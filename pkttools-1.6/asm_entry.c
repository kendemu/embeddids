#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "asm_val.h"
#include "asm_field.h"
#include "asm_entry.h"
#include "lib.h"

pkt_asm_entry_t pkt_asm_entry_create(pkt_asm_field_t field, pkt_asm_val_t val)
{
  pkt_asm_entry_t entry;

  entry = malloc(sizeof(*entry));
  if (entry == NULL)
    error_exit("Out of memory.\n");

  memset(entry, 0, sizeof(*entry));

  entry->next = NULL;
  entry->field = field;
  entry->val = val;

  return entry;
}

pkt_asm_entry_t pkt_asm_entry_destroy(pkt_asm_entry_t entry)
{
  if (entry) {
    if (entry->val)
      pkt_asm_val_destroy(entry->val);
    free(entry);
  }
  return NULL;
}
