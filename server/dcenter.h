#ifndef __DAGENT_H__
#define __DAGENT_H__

#include "util.h"

#define DC_VERSION	20150708

#define DA_LISTENPORT 9999
#define DA_BACKLOG 5

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


/* recv buffer */
typedef struct rzbuf_s
{
    char* buffer;
    unsigned int length;
} rzbuf_t;


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
} dcenter_cycle_t;

void dcenter_sock_init(void);
void dcenter_sock(void);
dcenter_cycle_t* cycle_init(void);

#endif /* __dagent_H__ */
