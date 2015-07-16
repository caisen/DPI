#ifndef __DCENTER_H__
#define __DCENTER_H__

#include "util.h"

#define DC_VERSION	"1.2.1" 
#define DC_BACKLOG 5

/* max packet length */
#define MAX_PACKET_LEN 102400

#define MEM_SIZE    4096

struct sock_ev {
    struct event* read_ev;
    struct event* write_ev;
    char* buffer;
    int offset;
    int data_len;
    int read_data_flag;
};

/* dcenter connection */
typedef struct dcenter_sock_s
{
    BOOL idle;
    int sock_fd;
    BOOL status;
} dcenter_sock_t;

/* global cycle data */
typedef struct dcenter_cycle_s
{
    dcenter_sock_t *socks;
    pthread_mutex_t mutex;
    char *path;
    short lport;
    FILE *record_fd;
    char *date;
} dcenter_cycle_t;

void dcenter_sock_init(void);
void dcenter_sock(void);
dcenter_cycle_t* cycle_init(void);

#endif /* __DCENTER_H__ */
