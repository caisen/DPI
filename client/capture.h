#ifndef __CAPTURE_H__
#define __CAPTURE_H__

#include "dagent.h"

void* zsend(void* ptr);
int capture(const char* interface, const char* filter);
void dcenter_packet(http_request_t* req);
void core(u_char *param, const struct pcap_pkthdr *pkthdr, const u_char *raw_data);

#endif /* __CAPTURE_H__ */
