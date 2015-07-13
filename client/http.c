#include "http.h"

http_request_t* http_new_request(void)
{
	http_request_t *r = NULL;
	r = MALLOC(http_request_t, 1);
    
    r->proxy = FALSE;
    
	r->host = NULL;
	r->host_len = 0;
    
	r->cookie = NULL;
    r->cookie_len = 0;
    
	r->referer = NULL;
    r->referer_len = 0;
	
	r->uri = NULL;
	r->uri_len = 0;
    
	r->user_agent = NULL;
    r->x_requested_with = NULL;
    r->x_requested_with_len = 0;
    
	return r;
}


BOOL http_detect_get(u_char *data, int datalen)
{
    u_char* buf = data;
    
    if (datalen >= 2)
	{
		if (str2_cmp(buf, 'M', '-') || str2_cmp(buf, '\r', '\n'))
		{
			buf += 2;
			datalen -= 2;
		}
    }
    
	return str4_cmp(buf, 'G', 'E', 'T', ' ');
}


BOOL http_detect_filter_uri(const char* uri)
{
    /*
     hm.baidu.com/hm.gif
     *.wrating.com/a.gif
     nsclick.baidu.com/v.gif
     beacon.sina.com.cn/e.gif
     g.x.cn.miaozhen.com/x.gif
     g.x.cn.miaozhen.com/m.gif
     dw.cbsi.com.cn/clear/c.gif
     cm.masky.biddingx.com/masky/
     hotclick.app.linezing.com/hotclick.gif
     */
    if (str7_cmp(uri, '/', 'h', 'm', '.', 'g', 'i', 'f') || str6_cmp(uri, '/', 'a', '.', 'g', 'i', 'f')
        || str6_cmp(uri, '/', 'v', '.', 'g', 'i', 'f') || str6_cmp(uri, '/', 'e', '.', 'g', 'i', 'f')
        || str6_cmp(uri, '/', 'x', '.', 'g', 'i', 'f') || str7_cmp(uri, '/', 'c', 'm', '.', 'g', 'i', 'f')
        || str9_cmp(uri, '/', 'j', 's', '/', '1', 'x', '1', '.', 'g') || str6_cmp(uri, '/', 'm', '.', 'g', 'i', 'f')
        || str9_cmp(uri, '/', 'c', 'l', 'e', 'a', 'r', '/', 'c', '.') || str7_cmp(uri, '/', 'm', 'a', 's', 'k', 'y', '/')
        || str9_cmp(uri, '/', 'h', 'o', 't', 'c', 'l', 'i', 'c', 'k'))
        return TRUE;
    else
        return FALSE;
}


BOOL http_detect_filter_host(const char *host)
{
    if (strcmp(host, "stats.ipinyou.com") == 0 || strcmp(host, "cm.ipinyou.com") == 0)
        return TRUE;
    else
        return FALSE;
}


BOOL http_detect_type(u_char *data, int datalen)
{
    u_char* buf = data;
	u_char *sep = NULL;
    
	if (datalen >= 2)
	{
		if (str2_cmp(buf, 'M', '-') || str2_cmp(buf, '\r', '\n'))
		{
			buf += 2;
			datalen -= 2;
		}
	}
    
	//detect URI
	sep = strchr(buf, '\r');
	if (sep == 0 || (sep - buf) < 12)
		return TRUE;
    
    buf = sep - 12;
    
    //tar/gz/tgz/zip/Z/7z/rpm/deb/ps/dvi/pdf/smi/png/jpg/jpeg/bmp/tiff/gif/mov/avi/mpeg/mpg/mp3/qt/wav/ram/rm/rmvb/jar/java/class/diff/doc/docx/xls/ppt/mdb/rtf/exe/pps/so/psd/css/js/ico/dll/bz2/rar
	if (str3_cmp(buf, 'g', 'i', 'f') || str3_cmp(buf, '.', 'j', 's') || str3_cmp(buf, 'j', 'p', 'g') || str3_cmp(buf, 'p', 'n', 'g')
        || str3_cmp(buf, 'b', 'm', 'p') || str3_cmp(buf, 'z', 'i', 'p') || str3_cmp(buf, 'r', 'a', 'r') || str3_cmp(buf, 'd', 'o', 'c')
        || str3_cmp(buf, 'x', 'l', 's') || str3_cmp(buf, 's', 'w', 'f') || str3_cmp(buf, 'c', 's', 's') || str3_cmp(buf, 'i', 'c', 'o')
        || str3_cmp(buf, 'f', 'l', 'v') || str3_cmp(buf, 'e', 'x', 'e') || str3_cmp(buf, 't', 'a', 'r') || str3_cmp(buf, 'd', 'l', 'l')
        || str3_cmp(buf, 't', 'g', 'z') || str3_cmp(buf, 'r', 'p', 'm') || str3_cmp(buf, 'a', 'v', 'i') || str3_cmp(buf, 'r', 't', 'f')
        || str3_cmp(buf, 'x', 'm', 'l') || str3_cmp(buf, 'm', 'p', 'g') || str3_cmp(buf, 'm', 'p', '4') || str3_cmp(buf, 'm', '4', 'v')
        || str3_cmp(buf, 'p', 'p', 't') || str3_cmp(buf, 'p', 's', 'd') || str3_cmp(buf, 'w', 'm', 'v') || str3_cmp(buf, 'p', 'e', 'g'))
	{
		return FALSE;
	}
    
	//detect URI
	sep = strchr(data, '.');
	if (sep == 0)
		return TRUE;
    
	buf = sep + 1;
	if (*buf == '\0' || *(buf + 1) == '\0')
		return TRUE;
    
	if (*(buf + 2) == '\0')
		return TRUE;
    
    //jpg/gif/png/bmp/zip/rar/doc/xls/swf/css/ico ---just match lower case
	if (str2_cmp(buf, 'j', 's') || str3_cmp(buf, 'j', 'p', 'g') || str3_cmp(buf, 'g', 'i', 'f') || str3_cmp(buf, 'p', 'n', 'g')
        || str3_cmp(buf, 'b', 'm', 'p') || str3_cmp(buf, 'z', 'i', 'p') || str3_cmp(buf, 'r', 'a', 'r') || str3_cmp(buf, 'f', 'l', 'v')
        || str3_cmp(buf, 'd', 'o', 'c') || str3_cmp(buf, 'c', 's', 's') || str3_cmp(buf, 's', 'w', 'f') || str3_cmp(buf, 'i', 'c', 'o')
        || str3_cmp(buf, 'x', 'm', 'l'))
	{
		return FALSE;
	}
    
	return TRUE;
}



BOOL http_detect_mime_type(http_request_t* r)
{
    u_char* buf = r->uri;
	u_char *sep = NULL;
    
    buf = r->uri + r->uri_len - 3;
    
    //tar/gz/tgz/zip/Z/7z/rpm/deb/ps/dvi/pdf/smi/png/jpg/jpeg/bmp/tiff/gif/mov/avi/mpeg/mpg/mp3/qt/wav/ram/rm/rmvb/jar/java/class/diff/doc/docx/xls/ppt/mdb/rtf/exe/pps/so/psd/css/js/ico/dll/bz2/rar
	if (str3_cmp(buf, 'g', 'i', 'f') || str3_cmp(buf, '.', 'j', 's') || str3_cmp(buf, 'j', 'p', 'g') || str3_cmp(buf, 'p', 'n', 'g')
        || str3_cmp(buf, 'b', 'm', 'p') || str3_cmp(buf, 'z', 'i', 'p') || str3_cmp(buf, 'r', 'a', 'r') || str3_cmp(buf, 'd', 'o', 'c')
        || str3_cmp(buf, 'x', 'l', 's') || str3_cmp(buf, 's', 'w', 'f') || str3_cmp(buf, 'c', 's', 's') || str3_cmp(buf, 'i', 'c', 'o')
        || str3_cmp(buf, 'f', 'l', 'v') || str3_cmp(buf, 'e', 'x', 'e') || str3_cmp(buf, 't', 'a', 'r') || str3_cmp(buf, 'd', 'l', 'l')
        || str3_cmp(buf, 't', 'g', 'z') || str3_cmp(buf, 'r', 'p', 'm') || str3_cmp(buf, 'a', 'v', 'i') || str3_cmp(buf, 'r', 't', 'f')
        || str3_cmp(buf, 'x', 'm', 'l') || str3_cmp(buf, 'm', 'p', 'g') || str3_cmp(buf, 'm', 'p', '4') || str3_cmp(buf, 'm', '4', 'v')
        || str3_cmp(buf, 'p', 'p', 't') || str3_cmp(buf, 'p', 's', 'd') || str3_cmp(buf, 'w', 'm', 'v') || str3_cmp(buf, 'p', 'e', 'g'))
	{
		return FALSE;
	}
    
	//detect URI
	sep = strchr(r->uri, '.');
	if (sep == 0)
		return TRUE;
    
	buf = sep + 1;
	if (*buf == '\0' || *(buf + 1) == '\0')
		return TRUE;
    
	if (*(buf + 2) == '\0')
		return TRUE;
    
    //jpg/gif/png/bmp/zip/rar/doc/xls/swf/css/ico ---just match lower case
	if (str2_cmp(buf, 'j', 's') || str3_cmp(buf, 'j', 'p', 'g') || str3_cmp(buf, 'g', 'i', 'f') || str3_cmp(buf, 'p', 'n', 'g')
        || str3_cmp(buf, 'b', 'm', 'p') || str3_cmp(buf, 'z', 'i', 'p') || str3_cmp(buf, 'r', 'a', 'r') || str3_cmp(buf, 'f', 'l', 'v')
        || str3_cmp(buf, 'd', 'o', 'c') || str3_cmp(buf, 'c', 's', 's') || str3_cmp(buf, 's', 'w', 'f') || str3_cmp(buf, 'i', 'c', 'o')
        || str3_cmp(buf, 'x', 'm', 'l'))
	{
		return FALSE;
	}
    
	return TRUE;
}


BOOL http_detect_map_agent(const char *agent)
{
    if (agent == NULL)
        return FALSE;
    
    return (strstr(agent, "Windows") == 0) ? FALSE : TRUE;
}


BOOL http_detect_agent(const char *agent)
{
    if (agent == NULL)
        return FALSE;
    
    //Android/iPad/iPhone/baiduboxapp ---ingore all mobile
    if (strstr(agent, "Android") != 0 || strstr(agent, "iPad") != 0 || strstr(agent, "iPhone") != 0 || strstr(agent, "baiduboxapp") != 0)
	{
		return FALSE;
	}
    
    //FireFox/MSIE/Safari/Chrome/Netscape/Opera/OmniWeb/Mozilla
    if (strstr(agent, "FireFox") != 0 || strstr(agent, "MSIE") != 0 || strstr(agent, "Safari") != 0 || strstr(agent, "Chrome") != 0 ||
        strstr(agent, "Netscape") != 0 || strstr(agent, "Opera") != 0 || strstr(agent, "OmniWeb") != 0 || strstr(agent, "Mozilla") != 0)
	{
		return TRUE;
	}
    
	return FALSE;
}


char* http_get_domain(const char *host)
{
    /* detect : */
    if (strchr(host, ':') != 0 || strchr(host, '.') == 0)
        return NULL;
    
    unsigned int i, len = strlen(host);
    if (len <= 15)  /* detect ip */
    {
        BOOL ip_flag = TRUE;
        for (i = 0; i < len; i++)
        {
            if (host[i] < 46 || host[i] > 57)
            {
                ip_flag = FALSE;
                break;
            }
        }
        
        if (ip_flag == TRUE)
            return (char*)host;
    }
    
    char *parta = (char *)host, *partb = NULL, *part = NULL;
    
    part = strchr(host, '.');
    part = part + 1;    /* skip . */
    partb = part;
    
    while ((part = strchr(part, '.')))
    {
        part = part + 1;
        
        if (strchr(part, '.') != 0)
        {
            parta = partb;
            partb = part;
        }
        else
        {
            if (str2_cmp(part, 'c', 'n') && partb != NULL &&
                (str3_cmp(partb,'c','o','m') || str3_cmp(partb,'o','r','g') || str3_cmp(partb,'n','e','t') || str3_cmp(partb,'g','o','v')))
            {
                if (parta != NULL)
                    return parta;
                else
                    return partb;
            }
            else
                return partb;
        }
    }
    
    return (char*)host;
}


int http_parse_get(http_request_t *r, u_char *data)
{
    /* rollback */
	r->host_len = 0;
	r->uri_len = 0;
    r->x_requested_with_len = 0;
    r->referer_len = 0;
    r->cookie_len = 0;
    r->proxy = FALSE;
    
    u_char* buf = data;
	u_char *sep = NULL;
	int len = 0, flag = 0;
	unsigned int cnt = 0;
	buf += 4;
    
	//detect URI
	sep = strchr(buf, ' ');
	if (sep == 0)
		return -1;
	
	len = sep - buf;
    
    if (len < MAX_URI_LEN)
    {
        bzero(r->uri, MAX_URI_LEN);
        
        r->uri_len = len;
        *(r->uri + len) = '\0';
        memcpy(r->uri, buf, len);
    }
	
	//start parse header
	buf = strstr(buf, "\r\n");
	while(buf != 0 && cnt < 6)
	{
		buf = buf + 2;
		
		if ( (*buf != '\0' && *(buf + 1) != '\0' && check_crlf(buf, 2)) || *buf == NULL)
			break;
        
		sep = strstr(buf, "\r\n");
		if (sep == 0)
        {
            flag = 1;
            
            sep = buf + strlen(buf);
        }
		
		switch(buf[0])
		{
			case 'H':
				if ((sep - buf > 7) && buf[3] == 't' && buf[4] == ':')			//Host: man.chinaunix.net
				{
					len = (buf[5] == ' ') ? 6 : 5;
					buf = buf + len;
                    
					len = sep - buf;
                    
                    if (len < MAX_HOST_LEN)
                    {
                        bzero(r->host, MAX_HOST_LEN);
                        
                        r->host_len = len;
                        *(r->host + len) = '\0';
                        memcpy(r->host, buf, len);
                    }
                    
					cnt++;
				}
				break;
                
			case 'U':
                if ((sep - buf > 12) && buf[5] == 'A' && buf[9] == 't' && buf[10] == ':')	//User-Agent: Mozilla/5.0 Firefox/21.0
				{
					len = (buf[11] == ' ') ? 12 : 11;
					buf = buf + len;
                    
					len = sep - buf;
                    
                    if (len < MAX_AGENT_LEN)
                    {
                        bzero(r->user_agent, MAX_AGENT_LEN);
                        
                        *(r->user_agent + len) = '\0';
                        memcpy(r->user_agent, buf, len);
                    }
                    
					cnt++;
				}
				break;
                
			case 'R':
				if ((sep - buf > 10) && buf[6] == 'r' && buf[7] == ':')	//Referer: http://man.chinaunix.net/develop/c&c++/linux_c/default.htm
				{
					len = (buf[8] == ' ') ? 9 : 8;
					buf = buf + len;
                    
					len = sep - buf;
                    
                    if (len < MAX_REF_LEN)
                    {
                        bzero(r->referer, MAX_REF_LEN);
                        
                        r->referer_len = len;
                        *(r->referer + len) = '\0';
                        memcpy(r->referer, buf, len);
                    }
                    
					cnt++;
				}
				break;
                
			case 'C':
				if ((sep - buf > 9) && buf[5] == 'e' && buf[6] == ':')	//Cookie: __utma=225341893.1493557647;
				{
					buf = buf + 7;
                    
					len = sep - buf;
                    
                    if (len < MAX_COOKIE_LEN)
                    {
                        bzero(r->cookie, MAX_COOKIE_LEN);
                        
                        r->cookie_len = len;
                        *(r->cookie + len) = '\0';
                        memcpy(r->cookie, buf, len);
                    }
                    
					cnt++;
				}
				break;
                
			case 'X':
            case 'x':
				if ((sep - buf > 30) && (buf[2] == 'r' || buf[2] == 'R') && buf[16] == ':')	//X-Requested-With: XMLHttpRequest\r\n
				{
					len = (buf[17] == ' ') ? 18 : 17;
					buf = buf + len;
                    
					len = sep - buf;
                    
                    if (len < MAX_REQ_WITH_LEN)
                    {
                        bzero(r->x_requested_with, MAX_REQ_WITH_LEN);
                        
                        r->x_requested_with_len = len;
                        *(r->x_requested_with + len) = '\0';
                        memcpy(r->x_requested_with, buf, len);
                    }
                    
					cnt++;
				}
                else if ((sep - buf > 20) && (buf[2] == 'f' || buf[2] == 'F') && buf[15] == ':') //X-Forwarded-For: client1, proxy1, proxy2。
                {
                    r->proxy = TRUE;
                    
					cnt++;
                }
                
				break;
                
			case 'V':
            case 'v':
				if ((sep - buf > 6) && (buf[2] == 'i' || buf[2] == 'I') && buf[3] == ':')	//Via: 1.1 BJNT3\r\n
				{
                    r->proxy = TRUE;
                    
					cnt++;
				}
				break;
		}
        
        if (flag == 1)
            break;
        
		buf = sep;
	}
    
	return 1;
}


void http_free_request(http_request_t *r)
{
	if(r->host != NULL)
		free(r->host);
    
	if(r->uri != NULL)
		free(r->uri);
    
	if(r->user_agent != NULL)
		free(r->user_agent);
    
	if(r->referer != NULL)
		free(r->referer);
    
	if(r->cookie != NULL)
		free(r->cookie);
    
    if (r->saddr_str != NULL)
        free(r->saddr_str);
    
    if (r->daddr_str != NULL)
        free(r->daddr_str);
    
    if (r->x_requested_with != NULL)
        free(r->x_requested_with);
    
	free(r);
}
