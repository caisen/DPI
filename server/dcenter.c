#include "dcenter.h"

dcenter_cycle_t *dcycle;
struct event_base* base;

int main(int argc, char *argv[])
{   
    /* libevent thread */
    evthread_use_pthreads();
    
    dcycle = cycle_init();
    
    /* signal process */
    signal(SIGPIPE, SIG_IGN);
    
    /* init dcenter sock */
    dcenter_sock_init();

    /* dcenter sock */
    dcenter_sock();
    
	return 0;
}

dagent_cycle_t* cycle_init()
{
    /* init dagent_cycle_t*/
    dcycle = MALLOC(dcenter_cycle_t, 1);
    
    /* init dcenter socket */
    dcycle->socks = NULL;
   
    /* init mutex */
	pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
	memcpy(&dcycle->mutex, &blank_mutex, sizeof(dcycle->mutex));
    
    return dcycle;
}

void dcenter_sock_init(void)
{
    dcenter_sock_t* sock = (dcenter_sock_t*)MALLOC(dcenter_sock_t, 1);
    sock->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    sock->idle = TRUE;

    struct sockaddr_in sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(DA_LISTENPORT);
    sockaddr.sin_addr.s_addr = INADDR_ANY;

    int flag = 1;
    setsockopt(sock->sock_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    if(-1 == bind(sock->sock_fd, (struct sockaddr*)&sockaddr, sizeof(struct sockaddr)))
    {
        close(sock->sock_fd);
		printf("bind(): can not bind server socket.\n");
        exit(0);
    }
	if(-1 == listen(sock->sock_fd, DA_BACKLOG)) 
    {
        close(sock->sock_fd);
		printf("listen(): can not listen server socket.\n");
        exit(0);
	}

    sock->status = TRUE;
}

void release_sock_event(struct sock_ev* ev)
{    
    event_del(ev->read_ev);    
    free(ev->read_ev);    
    free(ev->write_ev);    
    free(ev->buffer);    
    free(ev);
}

void do_read(int sock, short event, void* arg)
{
    struct event* write_ev;
    int size;
    struct sock_ev* ev = (struct sock_ev*)arg;

    size = recv(sock, ev->buffer+ev->offset, MEM_SIZE-ev->offset, 0);
    if (size == 0) {
        release_sock_event(ev);
        close(sock);
        return;
    }
    
    ev->offset += size;
    if((ev->offset>7)&& ev->read_data_flag==0)
    {
      ev->read_data_flag = 1;
      sscanf(ev->buffer, "%d\n", &ev->data_len);
      printf("receive size:%d\n",ev->data_len);
    }
    else if((ev->offset>(ev->data_len+7))&&(ev->read_data_flag==1))
    {
       // get data
       memcpy(ev->buffer,ev->buffer+ev->data_len+7,ev->offset-ev->data_len-7);
       ev->offset = ev->offset-ev->data_len-7;
       ev->read_data_flag = 0;
    }
    else if(ev->offset>MEM_SIZE)
    {
       release_sock_event(ev);
       close(sock);
       return;
    }


}

void do_accept(int sock, short event, void* arg)
{
    struct sockaddr_in cli_addr;
    int newfd, sin_size;
    
    struct sock_ev* ev = (struct sock_ev*)malloc(sizeof(struct sock_ev));
    ev->read_ev = (struct event*)malloc(sizeof(struct event));
    ev->write_ev = (struct event*)malloc(sizeof(struct event));
    ev->buffer = (char*)malloc(MEM_SIZE);
    bzero(ev->buffer, MEM_SIZE);
    ev->offset = 0;
    ev->data_len = 0;
    ev->read_data_flag = 0;
    sin_size = sizeof(struct sockaddr_in);
    newfd = accept(sock, (struct sockaddr*)&cli_addr, &sin_size);
    event_set(ev->read_ev, newfd, EV_READ|EV_PERSIST, do_read, ev);
    event_base_set(base, ev->read_ev);
    event_add(ev->read_ev, NULL);
}

void dcenter_sock(void)
{
    dcenter_sock_t* sock = dcycle->socks;
    struct event listen_ev;

    base = event_base_new();
    event_set(&listen_ev, sock->sock_fd, EV_READ|EV_PERSIST, do_accept, NULL);
    event_base_set(base, &listen_ev);
    event_add(&listen_ev, NULL);
    event_base_dispatch(base);

}

