/* $Id: capture.h 80 2013-07-10 12:33:02Z libing $*/

#ifndef __CAPTURE_H__
#define __CAPTURE_H__

#include "dagent.h"

void* zsend(void* ptr);
int capture(const char* interface, const char* filter);
void dcenter_packet(http_request_t* req, char* cookie, unsigned int ip_id, int sport);
void core(u_char *param, const struct pcap_pkthdr *pkthdr, const u_char *raw_data);

#endif /* __CAPTURE_H__ */
