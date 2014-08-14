#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "pcap.h"
#include "lib.h"

struct pcap_file_header {
  pkt_uint32 magic;
#define PCAP_FILE_HEADER_MAGIC 0xA1B2C3D4
  pkt_uint16 version_major;
  pkt_uint16 version_minor;
#define PCAP_FILE_HEADER_VERSION_MAJOR 2
#define PCAP_FILE_HEADER_VERSION_MINOR 4
  pkt_int32 thiszone;
  pkt_uint32 sigfigs;
  pkt_uint32 snaplen;
#define PCAP_FILE_HEADER_SNAPLEN 0xFFFF
  pkt_uint32 linktype;
#define PCAP_FILE_HEADER_LINKTYPE_ETHERNET 1
};

struct pcap_packet_header {
  struct {
    pkt_uint32 tv_sec;
    pkt_uint32 tv_usec;
  } ts;
  pkt_uint32 caplen;
  pkt_uint32 len;
};

typedef union {
  pkt_uint32 w;
  pkt_uint16 h[2];
  pkt_uint8  b[4];
} eword_t;

static pkt_uint32 read_ne32(pkt_uint32 val)
{
  return val;
}

static pkt_uint16 read_ne16(pkt_uint16 val)
{
  return val;
}

static pkt_uint32 read_le32(pkt_uint32 val)
{
  eword_t ew;
  ew.w = val;
  return (ew.b[3] << 24) | (ew.b[2] << 16) | (ew.b[1] << 8) | ew.b[0];
}

static pkt_uint32 read_be32(pkt_uint32 val)
{
  eword_t ew;
  ew.w = val;
  return (ew.b[0] << 24) | (ew.b[1] << 16) | (ew.b[2] << 8) | ew.b[3];
}

static pkt_uint16 read_le16(pkt_uint16 val)
{
  eword_t ew;
  ew.h[0] = val;
  return (ew.b[1] << 8) | ew.b[0];
}

static pkt_uint16 read_be16(pkt_uint16 val)
{
  eword_t ew;
  ew.h[0] = val;
  return (ew.b[0] << 8) | ew.b[1];
}

typedef pkt_uint32 (*read_32_t)(pkt_uint32 val);
typedef pkt_uint16 (*read_16_t)(pkt_uint16 val);

static read_32_t read_32;
static read_16_t read_16;

static int read_file_header(FILE *fp)
{
  struct pcap_file_header filehdr;

  if (fread(&filehdr, sizeof(filehdr), 1, fp) == 0)
    return -1;

  if (filehdr.magic == PCAP_FILE_HEADER_MAGIC) {
    read_32 = read_ne32;
    read_16 = read_ne16;
  } else if (read_le32(filehdr.magic) == PCAP_FILE_HEADER_MAGIC) {
    read_32 = read_le32;
    read_16 = read_le16;
  } else if (read_be32(filehdr.magic) == PCAP_FILE_HEADER_MAGIC) {
    read_32 = read_be32;
    read_16 = read_be16;
  } else {
    error_exit("Invalid magic number.\n");
  }

  return 0;
}

static int read_packet_header(FILE *fp, struct pcap_packet_header *pkthdr)
{
  if (fread(pkthdr, sizeof(*pkthdr), 1, fp) == 0)
    return -1;

  pkthdr->ts.tv_sec  = read_32(pkthdr->ts.tv_sec);
  pkthdr->ts.tv_usec = read_32(pkthdr->ts.tv_usec);
  pkthdr->caplen     = read_32(pkthdr->caplen);
  pkthdr->len        = read_32(pkthdr->len);

  return 0;
}

static int write_file_header(FILE *fp)
{
  struct pcap_file_header filehdr;
  memset(&filehdr, 0, sizeof(filehdr));
  filehdr.magic = PCAP_FILE_HEADER_MAGIC;
  filehdr.version_major = PCAP_FILE_HEADER_VERSION_MAJOR;
  filehdr.version_minor = PCAP_FILE_HEADER_VERSION_MINOR;
  filehdr.snaplen = PCAP_FILE_HEADER_SNAPLEN;
  filehdr.linktype = PCAP_FILE_HEADER_LINKTYPE_ETHERNET;
  fwrite(&filehdr, sizeof(filehdr), 1, fp);
  return 0;
}

int pkt_pcap_read(FILE *fp, char *p, int size,
		  int *capsizep, int *origsizep, struct timeval *tm)
{
  static int init = 0;
  struct pcap_packet_header pkthdr;
  int capsize;

  if (!init) {
    if (read_file_header(fp) < 0)
      error_exit("Cannot read file header.\n");
    init++;
  }

  if (read_packet_header(fp, &pkthdr) < 0)
    return -1;

  capsize = pkthdr.caplen;
  if (capsize > size)
    error_exit("Out of buffer.\n");

  if (fread(p, capsize, 1, fp) == 0)
    error_exit("Cannot read packet data.\n");

  if (capsizep ) *capsizep  = capsize;
  if (origsizep) *origsizep = pkthdr.len;
  if (tm) {
    tm->tv_sec  = pkthdr.ts.tv_sec;
    tm->tv_usec = pkthdr.ts.tv_usec;
  }

  return capsize;
}

int pkt_pcap_write(FILE *fp, char *p,
		   int capsize, int origsize, struct timeval *tm)
{
  static int init = 0;
  struct pcap_packet_header pkthdr;

  if (!init) {
    write_file_header(fp);
    init++;
  }

  pkthdr.ts.tv_sec  = tm->tv_sec;
  pkthdr.ts.tv_usec = tm->tv_usec;
  pkthdr.caplen     = capsize;
  pkthdr.len        = origsize;

  if (fwrite(&pkthdr, sizeof(pkthdr), 1, fp) == 0)
    return -1;
  if (fwrite(p, capsize, 1, fp) == 0)
    return -1;

  fflush(fp);

  return capsize;
}
