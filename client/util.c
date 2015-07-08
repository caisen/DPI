/* $Id: util.c 169 2013-08-01 15:15:10Z libing $*/

#include "util.h"

/* simple wrapper around the malloc() function */
void *check_malloc(unsigned long size)
{
	void *ptr = NULL;
	if ((ptr = malloc(size)) == NULL)
		exit(1);
	
	memset(ptr, 0, size);

	return ptr;
}


/* daemonize */
int daemonize()
{
    int fd;
    
    switch (fork())
    {
        case -1:
            return (-1);
        case 0:
            break;
        default:
            _exit(EXIT_SUCCESS);
    }
    
    if (setsid() == -1)
        return (-1);
    
    if ((fd = open("/dev/null", O_RDWR, 0)) != -1)
    {
        if(dup2(fd, STDIN_FILENO) < 0)
        {
            printf("dup2 stdin");
            return (-1);
        }
        
        if(dup2(fd, STDOUT_FILENO) < 0)
        {
            printf("dup2 stdout");
            return (-1);
        }
        
        if(dup2(fd, STDERR_FILENO) < 0)
        {
            printf("dup2 stderr");
            return (-1);
        }
        
        if (fd > STDERR_FILENO)
        {
            if(close(fd) < 0)
            {
                printf("close");
                return (-1);
            }
        }
    }
    
    return (0);
}


char *ip_ntos(u_int32_t n)
{
	char *buf = (char *)MALLOC(char, 16);

	sprintf(buf, "%d.%d.%d.%d", (n & 0xff000000) >> 24, (n & 0x00ff0000) >> 16, (n & 0x0000ff00) >> 8, (n & 0x000000ff) >> 0);

	return buf;
}


char *ip_buf_ntos(char *buf, u_int32_t n)
{    
	sprintf(buf, "%d.%d.%d.%d", (n & 0xff000000) >> 24, (n & 0x00ff0000) >> 16, (n & 0x0000ff00) >> 8, (n & 0x000000ff) >> 0);
    
	return buf;
}


char* http_find_header(char* uri, char* key, char* buf)
{
    char* sep = strstr(uri, key);
    if (sep != 0 && (*(sep-1) == '&' || *(sep-1) == '?'))
    {
        int len = 0;
        int klen = strlen(key);
        char* slp = strchr(sep, '&');   //viewIndex=1
        len = (slp != 0) ? (slp - sep - klen) : (strlen(uri) - klen - (sep - uri));
        
        if (len > 0 && len < MAX_QUERY_SIZE)
        {
            bzero(buf, MAX_QUERY_SIZE);
            
            memcpy(buf, sep+klen, len);
            
            return evhttp_uridecode(buf, 1, NULL);
        }
        else
            return NULL;
    }
    else if (sep != 0 && *(sep-1) != '&' && *(sep-1) != '?')
        return http_find_header((sep+1), key, buf);
    else
        return NULL;
}


char* decode_str(char* item)
{
    char* item_bak = item;
    
    int cs = (int)*item;
    int c = (cs < 104) ? 1 : ((cs < 115) ? 2: 3);
    
    item++;
    
    int i = 0;
    int len = strlen(item);
    for (i = 1; i <= len; i++)
    {
        cs = (int)*item;
        
        *item = (cs - c);
        
        item++;
    }
    
    return item_bak;
}


char* encode_str(char* item)
{
    char* item_bak = item;
    
    int cs = (int)*item;
    int c = (cs < 104) ? 1 : ((cs < 115) ? 2: 3);
    
    item++;
    
    int i = 0;
    int len = strlen(item);
    for (i = 1; i <= len; i++)
    {
        cs = (int)*item;
        
        *item = (cs + c);
        
        item++;
    }
    
    return item_bak;
}
