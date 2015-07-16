#ifndef __HTTP_H__
#define __HTTP_H__

#include "util.h"

/* http request fieled lentgh */
#define MAX_HOST_LEN        128
#define MAX_URI_LEN         4096
#define MAX_AGENT_LEN       1024
#define MAX_REF_LEN         1024
#define MAX_COOKIE_LEN      4096
#define MAX_REQ_WITH_LEN    512

/*
 * HTTP version.
 */
typedef enum _http_version
{
    HTTP_VER_1_0,
    HTTP_VER_1_1,
    HTTP_VER_NONE
} http_version;

/*
 * HTTP request header
 */
typedef struct http_request_s
{
    BOOL            proxy;
    
	char*			host;
	unsigned int	host_len;
    
	char*			uri;
	unsigned int	uri_len;
    
	char*			referer;
    unsigned int    referer_len;
    
    char*			cookie;
    unsigned int    cookie_len;
    
	char*			user_agent;
    unsigned int    user_agent_len;
    
	char*           saddr_str;
    char*           daddr_str;
    
    char*           x_requested_with;
    unsigned int	x_requested_with_len;
    
} http_request_t;

http_request_t* http_new_request(void);         /* create a new http_request_t object */
void http_free_request(http_request_t *r);      /* free a http_request_t object */
BOOL http_detect_get(u_char *p, int datalen);	/* if the packet is carrying HTTP GET request data */
BOOL http_detect_type(u_char *p, int datalen);
BOOL http_detect_filter_host(const char *host);
BOOL http_detect_mime_type(http_request_t* r);
BOOL http_detect_filter_uri(const char* uri);
BOOL http_detect_agent(const char *agent);        /* check the user agent */
BOOL http_detect_map_agent(const char *agent);    /* ingore Macintosh and Linux */
char* http_get_domain(const char *host);          /* get domain name from host */
int http_parse_get(http_request_t *r, u_char *data);	/* parse the packet and store in a request_t object */
int http_parse_line(http_request_t *r, char* line);     /* parse a line format for socket soure */

#endif /* __HTTP_H__ */
