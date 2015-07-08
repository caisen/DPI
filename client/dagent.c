/* $Id: dagent.h 151 2013-07-26 15:03:51Z libing $*/

#include "dagent.h"
#include "capture.h"

dagent_cycle_t *dcycle;

int main(int argc, char *argv[])
{
    char* host = NULL;
    short port = 0;
	char* interface = NULL;
    char* pcap_file = NULL;
    
    int opt;
	while((opt = getopt(argc, argv, "i:p:P:h:m:tSf:")) != -1)
	{
		switch(opt)
		{
            case 'i':
                interface = strdup(optarg);
                break;
                
            case 'h':
                host = strdup(optarg);
                break;
                
            case 'p':
                port = (short)atoi(optarg);
                break;
                
            case 'f':
                pcap_file = strdup(optarg);
                break;
                
            default:	/* '?' */
                printf("dagent version:%d \nusage: %s -h sync_host -p sync_port -i ethx -f pcap_file \n", DA_VERSION, argv[0]);
                return 1;
		}
	}

	if (host == NULL || port <= 0 || (interface == NULL && pcap_file == NULL))
	{
        printf("dagent version:%d \nusage: %s -h sync_host -p sync_port -i ethx -f pcap_file \n", DA_VERSION, argv[0]);
		return 1;
	}
    
    /* libevent thread */
    evthread_use_pthreads();
    
    dcycle = cycle_init();
    dcycle->interface = (interface != NULL) ? strdup(interface) : NULL;
    dcycle->pcap_file = (pcap_file != NULL) ? strdup(pcap_file) : NULL;
    
    /* set work mode */
    dcycle->port = port;
    dcycle->host = strdup(host);
    
    /* signal process */
    signal(SIGPIPE, SIG_IGN);
	
    /* load host */
    load_host_sample();
    
    /* init dcenter sock */
    dcenter_sock_init();
    
	pthread_t pt_health;
	pthread_create(&pt_health, NULL, health, NULL);
    
    /* work mode */
    capture(interface, DA_FILTER);
    
    void *pt_res;
	pthread_join(pt_health, &pt_res);
    
	return 0;
}


dagent_cycle_t* cycle_init()
{
    /* init dagent_cycle_t*/
    dcycle = MALLOC(dagent_cycle_t, 1);
    
	/* init buffer */
    dcycle->length = 0;
	dcycle->buffer = (char*)MALLOC(char, MAX_PACKET_LEN);
    
    /* top site hash map */
    dcycle->sites = hashmap_create(SITE_BUCKETS);
    
    /* init dcenter socket */
    dcycle->socks = NULL;
    
    /* init timestamp */
    time_t tt;
    time(&tt);
    dcycle->timestamp = mktime(localtime(&tt));
    
    /* init req buffer */
    dcycle->req = http_new_request();
    dcycle->req->host = (char *)MALLOC(char, MAX_HOST_LEN);
    dcycle->req->referer = (char *)MALLOC(char, MAX_REF_LEN);
    dcycle->req->uri = (char *)MALLOC(char, MAX_URI_LEN);
    dcycle->req->user_agent = (char *)MALLOC(char, MAX_AGENT_LEN);
    dcycle->req->x_requested_with = (char *)MALLOC(char, MAX_REQ_WITH_LEN);
    dcycle->req->cookie = (char *)MALLOC(char, MAX_COOKIE_LEN);
    dcycle->req->saddr_str = (char *)MALLOC(char, 16);
    dcycle->req->daddr_str = (char *)MALLOC(char, 16);
    
    /* init mutex */
	pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
	memcpy(&dcycle->mutex, &blank_mutex, sizeof(dcycle->mutex));
    
    return dcycle;
}


/* health check thread and reset count */
void* health(void* ptr)
{
    struct event_base* eb = event_base_new();
    
    dop_timer_t* tt = MALLOC(dop_timer_t, 1);
    tt->tv.tv_sec = 1;
    tt->tv.tv_usec = 0;
    tt->timer = evtimer_new(eb, dcenter_health_check, tt);
    evtimer_add(tt->timer, &(tt->tv));
    
    event_base_dispatch(eb);
}


void dcenter_health_check(int fd, short event, void* arg)
{
    /* update cycle timestamp */
    time_t ts;
    time(&ts);
    dcycle->timestamp = mktime(localtime(&ts));
        
    /* dcenter health check */
    dop_timer_t* tt = (dop_timer_t*)arg;
    
    dcenter_sock_t* sock = dcycle->socks;
    while (sock != NULL)
    {
        if (sock->status == FALSE || sock->sock_fd == -1)
        {
            if (sock->sock_fd != -1)
                close(sock->sock_fd);
            
            sock->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
            
            struct sockaddr_in sockaddr;
            sockaddr.sin_family = AF_INET;
            sockaddr.sin_port = htons(dcycle->port);
            sockaddr.sin_addr.s_addr = inet_addr(dcycle->host);
            
            int flag = 1;
            setsockopt(sock->sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag) );
            if (-1 != connect(sock->sock_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)))
                sock->status = TRUE;
            
            sock->idle = TRUE;
        }
        
        sock = sock->prev;
    }
    
    evtimer_add(tt->timer, &(tt->tv));
}


void dcenter_sock_init(void)
{
    int i = 0;
    for (; i < DA_SOCK_NUM; i++)
    {
        dcenter_sock_t* sock = (dcenter_sock_t*)MALLOC(dcenter_sock_t, 1);
        
        sock->prev = NULL;
        sock->next = NULL;
        sock->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        sock->idle = TRUE;
        
        struct sockaddr_in sockaddr;
        sockaddr.sin_family = AF_INET;
        sockaddr.sin_port = htons(dcycle->port);
        sockaddr.sin_addr.s_addr = inet_addr(dcycle->host);
        
        int flag = 1;
        setsockopt(sock->sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag) );
        if (-1 != connect(sock->sock_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)))
            sock->status = TRUE;

        if (dcycle->socks == NULL)
            dcycle->socks = sock;
        else
        {
            sock->prev = dcycle->socks;
            dcycle->socks->next = sock;
        }
        
        dcycle->socks = sock;
    }
}


dcenter_sock_t* pick_dcenter_sock(void)
{
    dcenter_sock_t* sock = dcycle->socks;
    
    pthread_mutex_lock(&dcycle->mutex);
    
    while (sock != NULL)
    {
        if (sock->idle == TRUE)
            break;
        else
            sock = sock->prev;
    }
    
    /* no idle */
    if (sock == NULL)
    {
        sock = (dcenter_sock_t*)MALLOC(dcenter_sock_t, 1);
        
        sock->prev = NULL;
        sock->next = NULL;
        sock->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        sock->idle = TRUE;
        
        struct sockaddr_in sockaddr;
        sockaddr.sin_family = AF_INET;
        sockaddr.sin_port = htons(dcycle->port);
        sockaddr.sin_addr.s_addr = inet_addr(dcycle->host);
        
        int flag = 1;
        setsockopt(sock->sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag) );
        if (-1 != connect(sock->sock_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)))
            sock->status = TRUE;
        
        if (dcycle->socks == NULL)
            dcycle->socks = sock;
        else
        {
            sock->prev = dcycle->socks;
            dcycle->socks->next = sock;
        }
        
        dcycle->socks = sock;
    }
    
    sock->idle = FALSE;
    
    pthread_mutex_unlock(&dcycle->mutex);
    
    return sock;
}


void load_host_sample()
{
    FILE * fp = NULL;
    unsigned int length = 0;
    
    char* line = (char*)malloc(1024);
    char* line_bak = line;
    
    /* load host */
    site_t *site = NULL;
    unsigned int fpos = 0;
    char host[256] = {0}, cname[256] = {0};
    int cnt = 0, type;
    
    fp = fopen(SAMPLE_HOST_FILE, "rb");
    if (fp == NULL)
        exit(0);
    
    while (fread(&length, 4, 1, fp) > 0)
    {
        line = line_bak;
        
        bzero(line, 1024);
        fread(line, 1, length, fp);
        
        line = decode_str(line);
        
        fpos = fpos + 4 + length;
        
        line++;
        
        ssize_t len = sscanf(line,"%[^\t\n]\t%d\t%[^\t\n]", host, &type, cname);
        if (len > 0)
        {
            site = (site_t *) MALLOC(site_t, 1);
            site->host = strdup(host);
            site->type = type;
            site->cname = strdup(cname);
            
            if (str4_cmp(site->cname, 'N', 'U', 'L', 'L'))
            {
                site->pcname = NULL;
                site->pcname_len = 0;
            }
            else
            {
                site->pcname = (char*)MALLOC(char, strlen(site->cname) + 1);
                site->pcname_len = sprintf(site->pcname, "%s=", site->cname);
            }
            
            hashmap_insert(dcycle->sites, site->host, site, sizeof(site_t));
            
            cnt++;
        }
        
        if (feof(fp))
            break;
    }
    
    free(line_bak);
}

