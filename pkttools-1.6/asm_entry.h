#ifndef _PKTTOOLS_ASM_ENTRY_H_INCLUDED_
#define _PKTTOOLS_ASM_ENTRY_H_INCLUDED_

struct pkt_asm_entry {
  struct pkt_asm_entry *next;
  pkt_asm_field_t field;
  pkt_asm_val_t val;
};

typedef struct pkt_asm_entry *pkt_asm_entry_t;

pkt_asm_entry_t pkt_asm_entry_create(pkt_asm_field_t field, pkt_asm_val_t val);
pkt_asm_entry_t pkt_asm_entry_destroy(pkt_asm_entry_t entry);

#endif
