#PCAP
#CFLAGS = -UENABLE_STAT_ONLY -UENABLE_LIBNET_LINK -UENABLE_MAC_SPECIFIED -UENABLE_DEBUG -Wall -O2
#LDFLAGS = -L/usr/lib -L/usr/lib64/ -lpcap -lnet

#PFRING
CFLAGS = -Wall -g -O0
LDFLAGS = -L/usr/lib -L/usr/lib64/ -L/usr/local/lib/ /usr/local/lib/libpcap.a  /usr/local/lib/libpfring.a -lnet -lrt -lpthread -levent -levent_pthreads -lz

TARGET=dagent
OBJS=capture.o  dagent.o  http.o  util.o

$(TARGET):$(OBJS)
	gcc  -o $(TARGET) $(OBJS) $(LDFLAGS)
.c.o:
	gcc -c -o $*.o $(CFLAGS) $<
clean:
	rm -rf $(TARGET) $(OBJS)
install:
	cp $(TARGET) /etc/$(TARGET)

