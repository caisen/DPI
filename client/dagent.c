#include "dagent.h"
#include "capture.h"

dagent_cycle_t *dcycle;

int main(int argc, char *argv[])
{
    char* host = NULL;
    short port = 0;
	char* interface = NULL;
    char* conf;
	int udp_flag = 0;
    
    int opt;
	while((opt = getopt(argc, argv, "u:c:i:p:P:h:m:tSf:")) != -1)
	{
		switch(opt)
		{
		    case 'c':
                conf = strdup(optarg);
                break;
            case 'i':
                interface = strdup(optarg);
                break;
                
            case 'h':
                host = strdup(optarg);
                break;
                
            case 'p':
                port = (short)atoi(optarg);
                break;
			case 'u':
					udp_flag = 1;
					break;

                
            default:	/* '?' */
                printf("dagent version:%s \nusage: %s -c conf_file -h sync_host -p sync_port -i ethx \n", DA_VERSION, argv[0]);
                return 1;
		}
	}

	if (host == NULL || port <= 0 || (interface == NULL))
	{
        printf("dagent version:%s \nusage: %s -c conf_file -h sync_host -p sync_port -i ethx \n", DA_VERSION, argv[0]);
		return 1;
	}
    
    /* libevent thread */
    evthread_use_pthreads();
    
    dcycle = cycle_init();
	dcycle->udp_flag = udp_flag;
    dcycle->interface = (interface != NULL) ? strdup(interface) : NULL;
    dcycle->conf = (conf != NULL) ? strdup(conf) : NULL;
    
    /* set work mode */
    dcycle->port = port;
    dcycle->host = strdup(host);
    
    /* signal process */
    signal(SIGPIPE, SIG_IGN);
	
    /* load host */
    load_host_sample();
    
    /* init dcenter sock */
	if(dcycle->udp_flag==1)
	{
		dcenter_sock_udp_init();
	}
	else
	{
		dcenter_sock_tcp_init();
	}
    
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
    dcycle->req->url = (char *)MALLOC(char, MAX_URI_LEN);
    dcycle->req->user_agent = (char *)MALLOC(char, MAX_AGENT_LEN);
    dcycle->req->x_requested_with = (char *)MALLOC(char, MAX_REQ_WITH_LEN);
    dcycle->req->cookie = (char *)MALLOC(char, MAX_COOKIE_LEN);
    dcycle->req->saddr_str = (char *)MALLOC(char, 16);
    dcycle->req->daddr_str = (char *)MALLOC(char, 16);
    
    /* init mutex */
	pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
	memcpy(&dcycle->mutex, &blank_mutex, sizeof(dcycle->mutex));

    //白名单过滤开关默认关闭
    dcycle->white_url_flag = FALSE;

    /* 快速匹配的hash表 */
    dcycle->hashmap = hashmap_create(MAX_BUCKETS);
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
    return 0;
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
            
            
			if(dcycle->udp_flag!=1)
			{
				sock->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
				struct sockaddr_in sockaddr;
            	sockaddr.sin_family = AF_INET;
            	sockaddr.sin_port = htons(dcycle->port);
            	sockaddr.sin_addr.s_addr = inet_addr(dcycle->host);
            
            	int flag = 1;
            	setsockopt(sock->sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag) );
            	if (-1 != connect(sock->sock_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)))
                	sock->status = TRUE;
			}
			else
				sock->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

            sock->idle = TRUE;
        }
        
        sock = sock->prev;
    }
    
    evtimer_add(tt->timer, &(tt->tv));
}


void dcenter_sock_tcp_init(void)
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


void dcenter_sock_udp_init(void)
{
    int i = 0;
    for (; i < DA_SOCK_NUM; i++)
    {
        dcenter_sock_t* sock = (dcenter_sock_t*)MALLOC(dcenter_sock_t, 1);
        
        sock->prev = NULL;
        sock->next = NULL;
        sock->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
        sock->idle = TRUE;

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
        sock->idle = TRUE;

		if(dcycle->udp_flag!=1)
		{		
			sock->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
       		struct sockaddr_in sockaddr;
        	sockaddr.sin_family = AF_INET;
        	sockaddr.sin_port = htons(dcycle->port);
        	sockaddr.sin_addr.s_addr = inet_addr(dcycle->host);
        
        	int flag = 1;
        	setsockopt(sock->sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag) );
        	if (-1 != connect(sock->sock_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)))
            	sock->status = TRUE;
		}
		else
			sock->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
		
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
    char line[MAX_BUFFER_LEN] = {0};
    char host[MAX_BUFFER_LEN] = {0};
    char url[MAX_BUFFER_LEN] = {0};
    char white_url[MAX_BUFFER_LEN] = {0};

    char *p = line;
    
    fp = fopen(dcycle->conf, "r");
    if (fp == NULL)
    {
        printf("Open dagent.conf failed!\n");
        exit(0);
    }

    while (fgets(p, MAX_BUFFER_LEN, fp))
    {
        if(STREQ(p, "host="))
        {
            memset(host,'\0',MAX_BUFFER_LEN);
            memset(url,'\0',MAX_BUFFER_LEN);
            sscanf(p, "host=%s url=%s\n", host, url);
            if(strlen(host)==0||strlen(url)==0)
            {
                printf("Line should not be empty: [%s]\n",p);
                continue;
            }

            regex_t reg_url;
            if (0 != regcomp(&reg_url, url, (REG_EXTENDED|REG_ICASE|REG_NOSUB))) 
            {
                printf("Regcomp url faild: [%s]\n",p);
                continue;
            }

            hashmap_insert(dcycle->hashmap, host, &reg_url, sizeof(regex_t));
        }
        else if(STREQ(p, "white_url="))
        {
            memset(white_url,'\0',MAX_BUFFER_LEN);
            sscanf(p, "white_url=%s\n", white_url);
            if((strlen(white_url)==0)||(0 != regcomp(&dcycle->reg_white_url, white_url, (REG_EXTENDED|REG_ICASE|REG_NOSUB))))
            {
                printf("Line is empty or error: [%s]\n",p);
                continue;
            }
            else
            {
                dcycle->white_url_flag = TRUE;
            }
        }
        else
        {
            ;
        }
        
    }

    fclose(fp);
}

