#ifndef STARFLOW_AGGLEVELS_H
#define STARFLOW_AGGLEVELS_H

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define KEYLEN 13 // Length of key used in any flow tables. 

typedef void (*starflow_setKey_t)(char *keyBuf, const struct ip* ipHeader, const struct udphdr* udpOrtcpHeader);

void setKey_TEST(char *keyBuf, const struct ip* ipHeader, const struct udphdr* udpOrtcpHeader){
  memset(keyBuf, 0, KEYLEN);
  uint32_t tmp = (uint32_t)ipHeader->ip_src.s_addr & 0x000000FF;
  memcpy(&(keyBuf[0]), &tmp, 4);
  // memcpy(&(keyBuf[4]), &ipHeader->ip_dst, 4);
  // memcpy(&(keyBuf[8]), &udpOrtcpHeader->source, 2);
  // memcpy(&(keyBuf[10]), &udpOrtcpHeader->dest, 2);
  // memcpy(&(keyBuf[12]), &ipHeader->ip_p, 1);
}

void setKey_ORIGINAL(char *keyBuf, const struct ip* ipHeader, const struct udphdr* udpOrtcpHeader){
  memcpy(&(keyBuf[0]), &ipHeader->ip_src, 4);
  memcpy(&(keyBuf[4]), &ipHeader->ip_dst, 4);
  memcpy(&(keyBuf[8]), &udpOrtcpHeader->source, 2);
  memcpy(&(keyBuf[10]), &udpOrtcpHeader->dest, 2);
  memcpy(&(keyBuf[12]), &ipHeader->ip_p, 1);
}

void setKey_saturatedWorkload(char *keyBuf, const struct ip* ipHeader, const struct udphdr* udpOrtcpHeader){
  uint32_t src = ipHeader->ip_src.s_addr & htonl(0xFFFF0000);
  uint32_t dst = ipHeader->ip_dst.s_addr & htonl(0xFFFF0000);
  struct tcphdr *tcp;
  
  if (ipHeader->ip_p == 6) {
      tcp = (struct tcphdr *)udpOrtcpHeader;
      memcpy(&(keyBuf[0]), &src, 4);
      memcpy(&(keyBuf[4]), &dst, 4);
      memcpy(&(keyBuf[8]), &tcp->th_flags, 1);
  }
}

#define NUM_KEYGENS 1
starflow_setKey_t key_gens[NUM_KEYGENS] = {
    setKey_saturatedWorkload,
};

int cur_key_gen = 0;

/* Dispatch to current keygen */
void setKey(char *keyBuf, const struct ip* ipHeader, const struct udphdr* udpOrtcpHeader)
{
    memset(keyBuf, 0, KEYLEN);
    key_gens[cur_key_gen](keyBuf, ipHeader, udpOrtcpHeader);
}

#endif
