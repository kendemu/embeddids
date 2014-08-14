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

static char *ifname   = NULL;
static int bufsize    = PKT_BUFFER_SIZE_DEFAULT;
static int filrev     = ARGUMENT_FLAG_OFF;
static int waitusec   = 0;
static int complete   = ARGUMENT_FLAG_OFF;
static int interval   = ARGUMENT_FLAG_ON;
static int justbefore = ARGUMENT_FLAG_OFF;

static Argument args[] = {
  { "-b", ARGUMENT_TYPE_INTEGER , &bufsize    },
  { "-r", ARGUMENT_TYPE_FLAG_ON , &filrev     },
  { "-i", ARGUMENT_TYPE_STRING  , &ifname     },
  { "-w", ARGUMENT_TYPE_INTEGER , &waitusec   },
  { "-c", ARGUMENT_TYPE_FLAG_ON , &complete   },
  { "-f", ARGUMENT_TYPE_FLAG_OFF, &interval   },
  { "-j", ARGUMENT_TYPE_FLAG_ON , &justbefore },
  { NULL, ARGUMENT_TYPE_NONE    , NULL        },
};

static int timecmp(struct timeval *t0, struct timeval *t1)
{
  if (t0->tv_sec  > t1->tv_sec ) return  1;
  if (t0->tv_sec  < t1->tv_sec ) return -1;
  if (t0->tv_usec > t1->tv_usec) return  1;
  if (t0->tv_usec < t1->tv_usec) return -1;
  return 0;
}

static int timesub(struct timeval *td, struct timeval *t0, struct timeval *t1)
{
  struct timeval t;
  if (timecmp(t0, t1) < 0)
    return -1;
  t.tv_sec  = t0->tv_sec;
  t.tv_usec = t0->tv_usec;
  while (t.tv_usec < t1->tv_usec) {
    t.tv_sec--;
    t.tv_usec += 1000000;
  }
  td->tv_sec  = t.tv_sec  - t1->tv_sec;
  td->tv_usec = t.tv_usec - t1->tv_usec;
  return 0;
}

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
  struct timeval starttime, firsttime, nowtime, tm, t0, t1;
  pkt_asm_list_t list;
  int first = 1;

  argument_read(&argc, argv, args);
  if (ifname == NULL)
    error_exit("Unknown interface.\n");
  if (complete) flags |= PKT_SEND_FLAG_COMPLETE;
  if (interval) flags |= PKT_SEND_FLAG_INTERVAL;

  fd = pkthandler.open_send(ifname, flags);

  buffer = malloc(bufsize);
  if (buffer == NULL)
    error_exit("Out of memory.\n");

  while (!terminated) {
    list = pkt_asm_list_create();
    size = pkt_text_read(stdin, buffer, bufsize, NULL, NULL, &tm, list);
    if (size < 0)
      break;
    if (size == bufsize)
      error_exit("Out of buffer.\n");

    pkt_assemble_ethernet(list, buffer, size);
    list = pkt_asm_list_destroy(list);

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

    if ((flags & PKT_SEND_FLAG_INTERVAL) && (tm.tv_sec || tm.tv_usec)) {
      if (first) {
	firsttime.tv_sec  = tm.tv_sec;
	firsttime.tv_usec = tm.tv_usec;
	gettimeofday(&starttime, NULL);
	first = 0;
      } else {
	gettimeofday(&nowtime, NULL);
	if (timesub(&t0, &tm, &firsttime) == 0)
	  if (timesub(&t1, &nowtime, &starttime) == 0)
	    if (timesub(&t0, &t0, &t1) == 0)
	      select(0, NULL, NULL, NULL, &t0);
	if (justbefore) {
	  firsttime.tv_sec  = tm.tv_sec;
	  firsttime.tv_usec = tm.tv_usec;
	  starttime.tv_sec  = nowtime.tv_sec;
	  starttime.tv_usec = nowtime.tv_usec;
	}
      }
    }

    signal(SIGINT , sigint_handler);
    signal(SIGTERM, sigint_handler);
    pkthandler.send(fd, buffer, size);
    signal(SIGINT , SIG_DFL);
    signal(SIGTERM, SIG_DFL);

    if (waitusec > 0)
      usleep(waitusec);
  }

  free(buffer);

  close(fd);

  return 0;
}
