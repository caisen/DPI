#include "dcenter.h"

dcenter_cycle_t *dcycle;
struct event_base* base;

void usage(char *prog)
{
    fprintf(stderr, "Version:%s \nUsage: %s\n", DC_VERSION, prog);
    exit(-1);
}

void open_record_file()
{
	char fn[128] = {0};
    time_t ct;

	time(&ct);
	strftime(dcycle->date, 16, "%Y%m%d", localtime(&ct));
	sprintf(fn, "%s/%s", dcycle->path, dcycle->date);
	dcycle->record_fd = fopen(fn, "a");
	if (dcycle->record_fd == NULL)
	{
		printf("Failed to open %s.\n", fn);
		exit(-1);
	}
}

void  do_fp_cycle()
{
	FILE *old_fp = dcycle->record_fd;
    time_t ct;
    char ts[15]={0};
    
    time(&ct);
    strftime(ts, 16, "%Y%m%d", localtime(&ct));

    if(strncmp(ts,dcycle->date,8))//日期不同
    {
        open_record_file();
        fclose(old_fp);
    }
}

int main(int argc, char *argv[])
{
    short port = 0;
    char *path;
    
    int opt;
	while((opt = getopt(argc, argv, "f:p:P:h:m:tSf:")) != -1)
	{
		switch(opt)
		{
            case 'f':
                path = strdup(optarg);
                break;
                
            case 'p':
                port = (short)atoi(optarg);
                break;
                
            default:	/* '?' */
                printf("dcenter version:%s \nusage: %s -f save_file_path -p listen_port \n", DC_VERSION, argv[0]);
                return 1;
		}
	}

	if (path == NULL || port <= 0)
	{
        printf("dcenter version:%s \nusage: %s -f save_file_path -p listen_port \n", DC_VERSION, argv[0]);
		return 1;
	}

    /* libevent thread */
    evthread_use_pthreads();
    
    dcycle = cycle_init();
    dcycle->path = (path != NULL) ? strdup(path) : NULL;
    dcycle->lport = port;
    
    /* signal process */
    signal(SIGPIPE, SIG_IGN);

    open_record_file();
    
    /* init dcenter sock */
    dcenter_sock_init();

    /* dcenter sock */
    dcenter_sock();
    
	return 0;
}

dcenter_cycle_t* cycle_init()
{
    /* init dagent_cycle_t*/
    dcycle = MALLOC(dcenter_cycle_t, 1);
    
    /* init dcenter socket */
    dcycle->socks = NULL;

    dcycle->record_fd = NULL;

    dcycle->date = MALLOC(char,16);
   
    /* init mutex */
	pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
	memcpy(&dcycle->mutex, &blank_mutex, sizeof(dcycle->mutex));
    
    return dcycle;
}

void do_record(char* uzbuf, long uzlen)
{
    do_fp_cycle();
    fwrite(uzbuf,uzlen,1,dcycle->record_fd);
    pthread_mutex_lock(&dcycle->mutex);  
    fflush(dcycle->record_fd);
    pthread_mutex_unlock(&dcycle->mutex);
}

void dcenter_sock_init(void)
{
    dcenter_sock_t* sock = (dcenter_sock_t*)MALLOC(dcenter_sock_t, 1);
    sock->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    sock->idle = TRUE;

    struct sockaddr_in sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(dcycle->lport);
    sockaddr.sin_addr.s_addr = INADDR_ANY;

    int flag = 1;
    setsockopt(sock->sock_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    if(-1 == bind(sock->sock_fd, (struct sockaddr*)&sockaddr, sizeof(struct sockaddr)))
    {
        close(sock->sock_fd);
		printf("bind(): can not bind server socket.\n");
        exit(0);
    }
	if(-1 == listen(sock->sock_fd, DC_BACKLOG)) 
    {
        close(sock->sock_fd);
		printf("listen(): can not listen server socket.\n");
        exit(0);
	}

    dcycle->socks = sock;
    
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

void *uzrecv(void *ptr)
{
    pthread_detach(pthread_self());
    
    rcvbuf_t* revbuf = (rcvbuf_t*)ptr;
    
    char* uzbuf = (char*)MALLOC(char, MAX_PACKET_LEN);
    memset(uzbuf, '\0', MAX_PACKET_LEN);
    long uzlen = MAX_PACKET_LEN;
    int ret = uncompress((Bytef *)uzbuf, (uLongf *)&uzlen,(Bytef *) revbuf->buffer+7, revbuf->data_len);
    if( ret == Z_OK)  
    { 
        //printf("%s\n",uzbuf);
        do_record(uzbuf, uzlen);
    }  
    else
    {
        printf("zlib uncompress failed, len:%d status:%d\n", revbuf->data_len, ret);
    }

    free(revbuf->buffer);
    free(revbuf);
    free(uzbuf);
        
	pthread_exit(NULL);
}

void do_read(int sock, short event, void* arg)
{
    int size;
    struct sock_ev* ev = (struct sock_ev*)arg;

    size = recv(sock, ev->buffer+ev->offset, MAX_PACKET_LEN-ev->offset, 0);
    if (size == 0) {
        release_sock_event(ev);
        close(sock);
        return;
    }
    
    ev->offset += size;
    if((ev->offset>7)&& ev->read_data_flag==0)
    {
    //读取长度
      ev->read_data_flag = 1;
      sscanf(ev->buffer, "%d\n", &ev->data_len);
      ev->data_len=ev->data_len-1;
    }
    else if((ev->offset>=(ev->data_len+7))&&(ev->read_data_flag==1))
    {
        rcvbuf_t* rcvbuf = (rcvbuf_t*)MALLOC(rcvbuf_t, 1);
        rcvbuf->buffer = ev->buffer;
        rcvbuf->data_len = ev->data_len;
        rcvbuf->offset = ev->offset;

        ev->buffer = (char*)malloc(MAX_PACKET_LEN);
        //缓冲区中遗留的部分
        ev->offset = rcvbuf->offset-rcvbuf->data_len-7;
        memcpy(ev->buffer,rcvbuf->buffer+rcvbuf->data_len+7,ev->offset);
        ev->read_data_flag = 0;

       //解压缩
       pthread_t pt_uzrecv;
       pthread_create(&pt_uzrecv, NULL, uzrecv, rcvbuf);
    }
    else if(ev->offset>MAX_PACKET_LEN)
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
    ev->buffer = (char*)malloc(MAX_PACKET_LEN);
    bzero(ev->buffer, MAX_PACKET_LEN);
    ev->offset = 0;
    ev->data_len = 0;
    ev->read_data_flag = 0;
    sin_size = sizeof(struct sockaddr_in);
    newfd = accept(sock, (struct sockaddr*)&cli_addr, (socklen_t *)&sin_size);
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

