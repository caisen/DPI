/* $Id: capture.c 166 2013-07-28 05:49:23Z libing $*/

#include "dagent.h"
#include "capture.h"

extern dagent_cycle_t *dcycle;


/* Capture main function. */
int capture(const char* interface, const char* filter)
{
	pcap_t *cap = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    
    if (dcycle->pcap_file != NULL)
        cap = pcap_open_offline(dcycle->pcap_file, errbuf);
    else
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
        
        if (req->host_len <= 0 || req->uri_len <= 0 || http_detect_agent(req->user_agent) == FALSE)
            return;
        
        /* ignore no need type */
        if(http_detect_mime_type(req) == FALSE && http_detect_filter_uri(req->uri) == FALSE && http_detect_filter_host(req->host) == FALSE)
            return;
        
        /* check host and domain */
        site_t *site = NULL;
        ssize_t cnt = hashmap_entry_by_key(dcycle->sites, req->host, (void **) &site);
        if (cnt <= 0)
            cnt = hashmap_entry_by_key(dcycle->sites, http_get_domain(req->host), (void **) &site);
        
        if(site == NULL || site->type == DA_FILTER_TYPE)
            return;
        
        char* cookie = NULL;
        if (site->pcname != NULL && req->cookie_len > 0 && req->cookie != NULL && site->type >= 2)
        {
            cookie = strstr(req->cookie, site->pcname);    /* check uv cookie */
            if (cookie != 0 && (*(cookie + site->pcname_len) == ';' || *(cookie + site->pcname_len) == ' '))
                cookie = strstr(cookie + site->pcname_len, site->pcname);
            
            if (cookie != NULL)
            {
                char* sep = strchr(cookie, ';');
                if (sep != 0)
                    *(sep+1) = '\0';
            }
        }
        
        if ((site->pcname_len > 0 && cookie != NULL) || site->pcname_len == 0 || site->type < 2)
        {
            /* not search type, set uri to / */
            if (site->type != 2)
            {
                *(req->uri) = '/';
                *(req->uri+1) = '\0';
            }
            
            /* not cookie type, set referer to NULL */
            if (site->type != 3)
            {
                *(req->referer) = '0';
                *(req->referer+1) = '\0';
            }
            
            ip_buf_ntos(req->saddr_str, ntohl(ip->ip_src.s_addr));
            ip_buf_ntos(req->daddr_str, ntohl(ip->ip_dst.s_addr));
            
            dcenter_packet(req, cookie, ntohs(ip->ip_id), tcp->th_sport);
        }        
    }
}


/* 账号\t源IP\t源端口\tIP_ID\t目的IP\tURL\tREF\tUA\tCookie\t时间戳 */
void dcenter_packet(http_request_t* req, char* cookie, unsigned int ip_id, int sport)
{
    unsigned int ua_id = abs(hf_crc32(req->user_agent));
    char* mtag = http_detect_map_agent(req->user_agent) ? "1" : "0";
    
    char* buf = dcycle->buffer + dcycle->length;
    int len = sprintf(buf, "N\t%s\t%d\t%d\t%s\thttp://%s/%.*s\t%.*s\t%s%d\t %.*s\t%ld\n", req->saddr_str, sport, ip_id, req->daddr_str, req->host, MAX_REFERER_LEN, req->uri, MAX_REFERER_LEN, req->referer, mtag, ua_id, MAX_CVAL_LEN, cookie, dcycle->timestamp);
    
    dcycle->length = dcycle->length + len;
    if (dcycle->length >= (MAX_PACKET_LEN - 1024))
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


void* zsend(void* ptr)
{
    pthread_detach(pthread_self());
    
    dcenter_sock_t* sock = pick_dcenter_sock();
    
    sndbuf_t* sndbuf = (sndbuf_t*)ptr;
    
    char* zbuf = (char*)MALLOC(char, MAX_PACKET_LEN);
    unsigned long snplen = compressBound(sndbuf->length);
    int ret = compress2(zbuf, &snplen, sndbuf->buffer, sndbuf->length, 9);
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
