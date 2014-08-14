#ifndef _PKTTOOLS_ASM_LIST_H_INCLUDED_
#define _PKTTOOLS_ASM_LIST_H_INCLUDED_

typedef struct pkt_asm_list *pkt_asm_list_t;

pkt_asm_list_t pkt_asm_list_create();
pkt_asm_list_t pkt_asm_list_destroy(pkt_asm_list_t list);

pkt_asm_entry_t pkt_asm_list_get_head(pkt_asm_list_t list);
int pkt_asm_list_add_val(pkt_asm_list_t list, pkt_asm_field_t field,
			 pkt_asm_val_t val);
pkt_asm_val_t pkt_asm_list_del_val(pkt_asm_list_t list,
				   pkt_asm_field_t field);

#endif
