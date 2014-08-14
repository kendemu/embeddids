#ifndef _PKTTOOLS_TEXT_H_INCLUDED_
#define _PKTTOOLS_TEXT_H_INCLUDED_

struct timeval;
int pkt_text_read(FILE *fp, char *buffer, int size,
		  int *capsizep, int *origsizep, struct timeval *tp,
		  pkt_asm_list_t list);
int pkt_text_write(FILE *fp, char *buffer,
		   int capsize, int origsize, struct timeval *tp,
		   pkt_asm_list_t list);

int pkt_asm_list_read(pkt_asm_list_t list, pkt_asm_field_t field, FILE *fp);
int pkt_asm_list_write(pkt_asm_list_t list, FILE *fp);
int pkt_asm_list_read_args(pkt_asm_list_t list, int argc, char *argv[]);
int pkt_asm_list_filter_args(pkt_asm_list_t list, int argc, char *argv[]);

#endif
