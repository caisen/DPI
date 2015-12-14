#include "dagent.h"
#include "capture.h"
#include "hash.h"
#include "aes.h"

extern dagent_cycle_t *dcycle;


/* Capture main function. */
int capture(const char* interface, const char* filter)
{
	pcap_t *cap = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    
    cap = pcap_open_live(interface, 65535, 1, 1000, errbuf);
    
	if( cap == NULL)
		exit(1);
    
	/* if set filter */
	if (filter != NULL)
	{
		bpf_u_int32 netp = 0;
		struct bpf_program fp;
        
		if(pcap_compile(cap, &fp, filter, 0, netp) == -1)
			exit(1);
        
		/* set the compiled program as the filter */
		if(pcap_setfilter(cap, &fp) == -1)
			exit(1);
	}
    
    pcap_loop(cap, 0, core, NULL);
    
	return 0;
}


/* Parse packets' header information and return a packet_t object */
void core(u_char *param, const struct pcap_pkthdr *pkthdr, const u_char *raw_data)
{
    u_char 	*cp = (u_char *)raw_data;   
	struct ether_header *eth_hdr = (struct ether_header *) cp;
    int status = 0;
    
    /* only IP or PPP */
    u_int16_t ether_type = ntohs(eth_hdr->ether_type);
	if( ether_type != 0x0800 && ether_type != 0x8100)
		return;
    
	cp = cp + ETHER_HDR_LEN;
	
	/* check 802.1Q packet*/
	if (ether_type == 0x8100)
	{
		cp = cp + 2;
        
		if (cp[0] == 0x88 && cp[1] == 0x64)         /* PPPOE */
            cp = cp + 10;
        else if (cp[0] == 0x08 && cp[1] == 0x00)    /* VLAN */
            cp = cp + 2;
        else
			return;
	}
    
   	/* IP header */
	struct ip *ip = (void *) cp;
       
	cp = cp + (ip->ip_hl * 4);
    
    /* TCP Header */
    tcphdr *tcp = (tcphdr *) cp;
    u_int8_t tcp_hl = tcp->th_off * 4;
	u_int16_t tcp_dl = ntohs(ip->ip_len) - (ip->ip_hl * 4) - tcp_hl;
    
	/* parser HTTP GET traffic */
    cp = cp + tcp_hl;
    if (http_detect_get(cp, tcp_dl))
    {
        http_request_t *req = dcycle->req;
        http_parse_get(req, cp);        
        
        if (req->host_len <= 0 || req->uri_len <= 0)
            return;
        
        /* ignore no need type */
        if(http_detect_mime_type(req) == FALSE && http_detect_filter_uri(req->uri) == FALSE && http_detect_filter_host(req->host) == FALSE)
            return;

        /* ÒÀ¾ÝhostÎª¹Ø¼ü×ÖÔÚhash±íÖÐËÑÑ°¹æÔò */
        regex_t *reg_url = NULL;
        hashmap_entry_by_key((*dcycle).hashmap, req->host, (void **)&reg_url);
        if (NULL == reg_url)
        {
            /* ¸ù¾Ýhost¹Ø¼ü×ÖÎ´ÕÒµ½ÏàÓ¦µÄ¹æÔò£¬ÔÚÄ¬ÈÏ¹æÔòÖÐµÚ¶þ´Î²éÕÒ */
            hashmap_entry_by_key((*dcycle).hashmap, "null", (void **)&reg_url);
            if (NULL == reg_url)
            {
                return;
            }
        }
        status = regexec(reg_url, req->url, 0, NULL, 0);
        if (REG_NOMATCH == status)
        {
            return;
        }

        /* check white_list */
        if(dcycle->white_url_flag)
        {
            status = regexec(&dcycle->reg_white_url, req->url, 0, NULL, 0);
            if (REG_NOMATCH != status)
            {
                return;
            }           
        }

		dcycle->count++;
        ip_buf_ntos(req->saddr_str, ntohl(ip->ip_src.s_addr));
        ip_buf_ntos(req->daddr_str, ntohl(ip->ip_dst.s_addr));
        if(dcycle->udp_flag==1)
        {
        	dcenter_udp_packet(req);
        }
		else
		{
			dcenter_tcp_packet(req);
		}
        
    }
}


/* è´¦å·\tæºIP\tæºç«¯å£\tIP_ID\tç›®çš„IP\tURL\tREF\tUA\tCookie\tæ—¶é—´æˆ³ */
void dcenter_tcp_packet(http_request_t* req)
{   
    char* buf = dcycle->buffer + dcycle->length;
    int len = sprintf(buf, "%s\t%s\t%s\thttp://%s\t%s\t%s\t%s\t%ld\n", req->saddr_str, req->daddr_str, req->host, req->url, req->referer, req->user_agent, req->cookie, dcycle->timestamp);
    
    dcycle->length = dcycle->length + len;
    if (dcycle->length >= (MAX_PACKET_LEN - 4096))
    {
        sndbuf_t* sndbuf = (sndbuf_t*)MALLOC(sndbuf_t, 1);
        sndbuf->buffer = dcycle->buffer;
        sndbuf->length = dcycle->length;
        
        /* reset buffer */
        dcycle->length = 0;
        dcycle->buffer = (char*)MALLOC(char, MAX_PACKET_LEN);
        
		pthread_t pt_zsend;
        pthread_create(&pt_zsend, NULL, zsend, sndbuf);
    }
}

void dcenter_udp_packet(http_request_t* req)
{   
    dcycle->length = sprintf(dcycle->buffer, "%s\n%s\n%s\n", req->saddr_str, req->url, req->user_agent);
	pthread_t pt_udp_send;
   	pthread_create(&pt_udp_send, NULL, udp_send, dcycle->buffer);
}

void* udp_send(void* ptr)
{
    pthread_detach(pthread_self());
 #if 1  
    dcenter_sock_t* sock = pick_dcenter_sock();
    
	/* send data */
	struct sockaddr_in sockaddr;
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(dcycle->port);
	sockaddr.sin_addr.s_addr = inet_addr(dcycle->host);

	if (sendto(sock->sock_fd, ptr, dcycle->length, 0,(struct sockaddr *)&sockaddr,sizeof(sockaddr)) == -1)
	{
		sock->sock_fd = -1;
		sock->status = FALSE;
	}  
    
    /* set idle */
    sock->idle = TRUE;
#else
	fwrite(dcycle->buffer, dcycle->length, 1, dcycle->log_fd);
	fflush(dcycle->log_fd);
#endif	
	pthread_exit(NULL);
}

void* zsend(void* ptr)
{
    pthread_detach(pthread_self());
    
    dcenter_sock_t* sock = pick_dcenter_sock();
    
    sndbuf_t* sndbuf = (sndbuf_t*)ptr;
    
    char* zbuf = (char*)MALLOC(char, MAX_PACKET_LEN);
    memset(zbuf,'\0',MAX_PACKET_LEN);
    unsigned long snplen = compressBound(sndbuf->length);
    int ret = compress2((Bytef *)zbuf, (uLongf *)&snplen, (Bytef *)sndbuf->buffer, sndbuf->length, 9);
    if (ret == Z_OK)
    {
        /* send packet header */
        sprintf(sndbuf->buffer, "%-6d\n", (snplen+1));
        send(sock->sock_fd, (void *)sndbuf->buffer, 7, 0);
        
        /* send compress data */
        if (send(sock->sock_fd, (void *)zbuf, snplen, 0) == -1)
        {
            sock->sock_fd = -1;
            sock->status = FALSE;
        }
    }
    else
        printf("zlib compress failed, len:%d status:%d :%s\n", sndbuf->length, ret, sndbuf->buffer);    
    
    /* set idle */
    sock->idle = TRUE;
    
    free(sndbuf->buffer);
    free(sndbuf);
    free(zbuf);
        
	pthread_exit(NULL);
}
