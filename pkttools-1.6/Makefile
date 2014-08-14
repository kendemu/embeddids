TARGET_RECV     = pkt-recv
TARGET_SEND     = pkt-send
TARGET_TXT2TXT  = pkt-txt2txt
TARGET_TXT2PCAP = pkt-txt2pcap
TARGET_PCAP2TXT = pkt-pcap2txt
TARGET_ANALYZE  = pkt-analyze
TARGET_CORRECT  = pkt-correct
TARGET_FILTER   = pkt-filter
TARGET_CHANGE   = pkt-change
TARGET_PINGREP  = pkt-pingrep

OBJS = argument.o bpf.o rawsock.o lib.o text.o pcap.o analyze.o correct.o \
	filter.o change.o pingrep.o assemble.o disasm.o \
	asm_val.o asm_field.o asm_entry.o asm_list.o

TARGETS = \
	$(TARGET_RECV) $(TARGET_SEND) \
	$(TARGET_TXT2TXT) $(TARGET_TXT2PCAP) $(TARGET_PCAP2TXT) \
	$(TARGET_ANALYZE) $(TARGET_CORRECT) $(TARGET_FILTER) $(TARGET_CHANGE) \
	$(TARGET_PINGREP)

LIB = libpkt.a

SRCS = $(OBJS:.o=.c)

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

CC ?= gcc
AR ?= ar

GFLAGS  = -O -Wall
GFLAGS += -g
CFLAGS  =
LFLAGS  = -L. -lpkt

.SUFFIXES:
.SUFFIXES: .o .c

all :		$(TARGETS)

.c.o :
		$(CC) $(GFLAGS) $(CFLAGS) $< -c -o $@

$(LIB) :	$(OBJS)
		$(AR) ruc $(LIB) $(OBJS)

$(TARGET_RECV) :	$(TARGET_RECV).o $(LIB)
		$(CC) $(TARGET_RECV).o $(GFLAGS) $(LFLAGS) -o $@

$(TARGET_SEND) :	$(TARGET_SEND).o $(LIB)
		$(CC) $(TARGET_SEND).o $(GFLAGS) $(LFLAGS) -o $@

$(TARGET_TXT2TXT) :	$(TARGET_TXT2TXT).o $(LIB)
		$(CC) $(TARGET_TXT2TXT).o $(GFLAGS) $(LFLAGS) -o $@

$(TARGET_TXT2PCAP) :	$(TARGET_TXT2PCAP).o $(LIB)
		$(CC) $(TARGET_TXT2PCAP).o $(GFLAGS) $(LFLAGS) -o $@

$(TARGET_PCAP2TXT) :	$(TARGET_PCAP2TXT).o $(LIB)
		$(CC) $(TARGET_PCAP2TXT).o $(GFLAGS) $(LFLAGS) -o $@

$(TARGET_ANALYZE) :	$(TARGET_ANALYZE).o $(LIB)
		$(CC) $(TARGET_ANALYZE).o $(GFLAGS) $(LFLAGS) -o $@

$(TARGET_CORRECT) :	$(TARGET_CORRECT).o $(LIB)
		$(CC) $(TARGET_CORRECT).o $(GFLAGS) $(LFLAGS) -o $@

$(TARGET_FILTER) :	$(TARGET_FILTER).o $(LIB)
		$(CC) $(TARGET_FILTER).o $(GFLAGS) $(LFLAGS) -o $@

$(TARGET_CHANGE) :	$(TARGET_CHANGE).o $(LIB)
		$(CC) $(TARGET_CHANGE).o $(GFLAGS) $(LFLAGS) -o $@

$(TARGET_PINGREP) :	$(TARGET_PINGREP).o $(LIB)
		$(CC) $(TARGET_PINGREP).o $(GFLAGS) $(LFLAGS) -o $@

install :	$(TARGETS)
		cp $(TARGETS) $(BINDIR)

uninstall :
		cd $(BINDIR) ; rm -f $(TARGETS) 

clean :
		rm -f $(OBJS) $(LIB) $(TARGETS)
		rm -f $(TARGET_RECV).o $(TARGET_SEND).o $(TARGET_TXT2TXT).o \
			$(TARGET_TXT2PCAP).o $(TARGET_PCAP2TXT).o \
			$(TARGET_ANALYZE).o $(TARGET_CORRECT).o \
			$(TARGET_FILTER).o $(TARGET_CHANGE).o \
			$(TARGET_PINGREP).o
