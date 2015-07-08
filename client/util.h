#ifndef __UTIL_H__
#define __UTIL_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <pcap/bpf.h>
#include <pcap/pcap.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>	
#include <assert.h>
#include <time.h> 
#include <stdlib.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <regex.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h> 
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>

#include <event.h>
#include <evhttp.h>
#include <event2/util.h>
#include <event2/event-config.h>
#include <event2/buffer.h>

#include <zlib.h>
#include <pthread.h>

#define SITE_BUCKETS 30000

#ifndef BOOL
#define BOOL int
#endif /* BOOL */

#ifndef TRUE
#define TRUE 1
#endif	/* TRUE */

#ifndef FALSE
#define FALSE 0
#endif	/* FALSE */

#define MAX_QUERY_SIZE 128

#define check_crlf(header, len)                                 \
  (((len) == 1 && header[0] == '\n') ||                         \
   ((len) == 2 && header[0] == '\r' && header[1] == '\n'))

#define str2_cmp(m, c0, c1)                                       \
    (m[0] == c0 && m[1] == c1)

#define str3_cmp(m, c0, c1, c2)                                       \
    (m[0] == c0 && m[1] == c1 && m[2] == c2)

#define str4_cmp(m, c0, c1, c2, c3)                                        \
    (m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3)

#define str5_cmp(m, c0, c1, c2, c3, c4)                                    \
    (m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3 && m[4] == c4)

#define str6_cmp(m, c0, c1, c2, c3, c4, c5)                                \
    (m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3                      \
    && m[4] == c4 && m[5] == c5)

#define str7_cmp(m, c0, c1, c2, c3, c4, c5, c6)                       \
    (m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3                      \
    && m[4] == c4 && m[5] == c5 && m[6] == c6)

#define str8_cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                        \
    (m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3                      \
    && m[4] == c4 && m[5] == c5 && m[6] == c6 && m[7] == c7)

#define str9_cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                    \
    (m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3                      \
    && m[4] == c4 && m[5] == c5 && m[6] == c6 && m[7] == c7 && m[8] == c8)

#define check_lws(header, len)	((len) > 0 && (header[0] == ' ' || header[0] == '\t'))

#define char_tolower(c)      (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)

#define MALLOC(type, num)  (type *) check_malloc((num) * sizeof(type))

#define STREQ(x, y)          (!strncmp((x), (y), strlen(y)))


/* TCP header structure */
typedef struct tcp_header
{
    u_int16_t th_sport;		/* Source port */
    u_int16_t th_dport;		/* Destination port */
    u_int32_t th_seq;		/* Sequence number */
    u_int32_t th_ack;		/* Acknowledgement number */
    u_int8_t th_x2:4;		/* (Unused) */
    u_int8_t th_off:4;		/* Data offset */
    u_int8_t th_flags;
#  define TH_FIN	0x01
#  define TH_SYN	0x02
#  define TH_RST	0x04
#  define TH_PUSH	0x08
#  define TH_ACK	0x10
#  define TH_URG	0x20
    u_int16_t th_win;		/* Window */
    u_int16_t th_sum;		/* Checksum */
    u_int16_t th_urp;		/* Urgent pointer */
} tcphdr;

int daemonize();
char* ip_ntos(u_int32_t n);
char* decode_str(char* item);
char* encode_str(char* item);
void* check_malloc(unsigned long size);
char* ip_buf_ntos(char *buf, u_int32_t n);
char* http_find_header(char* uri, char* key, char* buf);

/* site */
typedef struct sndbuf_s
{
    char* buffer;
    unsigned int length;
} sndbuf_t;

/* site */
typedef struct site_s
{
    char* host;
    
    char* cname;
    
    char* pcname;
    int pcname_len;
    
    int type;
} site_t;

/* timer */
typedef struct dop_timer_s
{
    struct event* timer;
    struct timeval tv;
} dop_timer_t;

#include "http.h"

#endif	/* __UTIL_H__ */
