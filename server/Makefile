CFLAGS = -Wall -g -O0
LDFLAGS = -L/usr/lib -L/usr/lib64/ -L/usr/local/lib/ -lrt -lpthread -levent -levent_pthreads  -lz

TARGET=dcenter
OBJS=dcenter.o util.o

$(TARGET):$(OBJS)
	gcc  -o $(TARGET) $(OBJS) $(LDFLAGS)
.c.o:
	gcc -c -o $*.o $(CFLAGS) $<
clean:
	rm -rf $(TARGET) $(OBJS)
install:
	cp $(TARGET) /etc/$(TARGET)

