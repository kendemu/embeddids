#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>

#include "argument.h"
#include "asm_val.h"
#include "asm_field.h"
#include "asm_entry.h"
#include "asm_list.h"
#include "assemble.h"
#include "disasm.h"
#include "text.h"
#include "lib.h"

static char *ifname = NULL;
static int bufsize  = 0;
static int filrev   = ARGUMENT_FLAG_OFF;
static int asmlist  = ARGUMENT_FLAG_OFF;
static int limit    = 0;
static int promisc  = ARGUMENT_FLAG_ON;
static int recvonly = ARGUMENT_FLAG_OFF;

static Argument args[] = {
  { "-b" , ARGUMENT_TYPE_INTEGER , &bufsize  },
  { "-r" , ARGUMENT_TYPE_FLAG_ON , &filrev   },
  { "-a" , ARGUMENT_TYPE_FLAG_ON , &asmlist  },
  { "-i" , ARGUMENT_TYPE_STRING  , &ifname   },
  { "-l" , ARGUMENT_TYPE_INTEGER , &limit    },
  { "-np", ARGUMENT_TYPE_FLAG_OFF, &promisc  },
  { "-ro", ARGUMENT_TYPE_FLAG_ON , &recvonly },
  { NULL , ARGUMENT_TYPE_NONE    , NULL      },
};

static int terminated = 0;
static void sigint_handler(int value)
{
  terminated = 1;
}

int main(int argc, char *argv[])
{
  unsigned long flags = 0;
  int fd, size, r;
  char *buffer;
  struct timeval tm;
  pkt_asm_list_t list;

  argument_read(&argc, argv, args);
  if (ifname == NULL)
    error_exit("Unknown interface.\n");
  if (promisc ) flags |= PKT_RECV_FLAG_PROMISC;
  if (recvonly) flags |= PKT_RECV_FLAG_RECVONLY;

  fd = pkthandler.open_recv(ifname, flags, bufsize ? NULL : &bufsize);

  buffer = malloc(bufsize);
  if (buffer == NULL)
    error_exit("Out of memory.\n");

  while (!terminated) {
    size = pkthandler.recv(fd, buffer, bufsize, &tm);
    if (size < 0)
      break;
    if (size == bufsize)
      error_exit("Out of buffer.\n");

    if (pkt_asm_list_filter_args(NULL, argc, argv) == 0) {
      list = pkt_asm_list_create();
      pkt_disasm_ethernet(list, buffer, size);
      r = pkt_asm_list_filter_args(list, argc, argv);
      list = pkt_asm_list_destroy(list);
      if (r >= 0) {
	if (filrev) r = !r;
	if (r == 0) continue;
      }
    }

    list = pkt_asm_list_create();
    pkt_asm_list_read_args(list, argc, argv);
    pkt_assemble_ethernet(list, buffer, size);
    list = pkt_asm_list_destroy(list);

    if (asmlist) {
      list = pkt_asm_list_create();
      pkt_disasm_ethernet(list, buffer, size);
    }

    signal(SIGINT , sigint_handler);
    signal(SIGTERM, sigint_handler);
    pkt_text_write(stdout, buffer, size, size, &tm, list);
    signal(SIGINT , SIG_DFL);
    signal(SIGTERM, SIG_DFL);

    list = pkt_asm_list_destroy(list);

    if (limit > 0) {
      if (--limit == 0)
	break;
    }
  }

  fflush(stdout);
  free(buffer);

  close(fd);

  return 0;
}
