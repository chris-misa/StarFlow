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

/* This aggregation level is for the Poisson-distributed queries --- each query rate saturates the possible aggregations so there's just one */
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


/*
 * Agg levels used in multiple-MRT heavy hitters tasks experiment
 * The mask numbers were generated with switch-module/evaluation/starflow/gen_agg_levels.py
 */

/* 1 task */
void setKey_tasks1(char *keyBuf, const struct ip* ipHeader, const struct udphdr* udpOrtcpHeader){
  uint32_t dst = ipHeader->ip_dst.s_addr & htonl(0xFFE00000);
  memcpy(&(keyBuf[4]), &dst, 4);
}

/* 2 tasks */
void setKey_tasks2(char *keyBuf, const struct ip* ipHeader, const struct udphdr* udpOrtcpHeader){
  uint32_t src = ipHeader->ip_src.s_addr & htonl(0xFF800000);
  memcpy(&(keyBuf[0]), &src, 4);
}

/* 3 tasks */
void setKey_tasks3(char *keyBuf, const struct ip* ipHeader, const struct udphdr* udpOrtcpHeader){
  uint32_t src = ipHeader->ip_src.s_addr & htonl(0xFFF80000);
  uint32_t dst = ipHeader->ip_dst.s_addr & htonl(0xF8000000);
  memcpy(&(keyBuf[0]), &src, 4);
  memcpy(&(keyBuf[4]), &dst, 4);
}

/* 4 tasks */
void setKey_tasks4(char *keyBuf, const struct ip* ipHeader, const struct udphdr* udpOrtcpHeader){
  uint32_t src = ipHeader->ip_src.s_addr & htonl(0xFFFC0000);
  uint32_t dst = ipHeader->ip_dst.s_addr & htonl(0xFC000000);
  memcpy(&(keyBuf[0]), &src, 4);
  memcpy(&(keyBuf[4]), &dst, 4);
}

/* 5 tasks */
void setKey_tasks5(char *keyBuf, const struct ip* ipHeader, const struct udphdr* udpOrtcpHeader){
  uint32_t src = ipHeader->ip_src.s_addr & htonl(0xFFE00000);
  uint32_t dst = ipHeader->ip_dst.s_addr & htonl(0xFFC00000);
  memcpy(&(keyBuf[0]), &src, 4);
  memcpy(&(keyBuf[4]), &dst, 4);
}

#define NUM_KEYGENS 5
starflow_setKey_t key_gens[NUM_KEYGENS] = {
    setKey_tasks1,
    setKey_tasks2,
    setKey_tasks3,
    setKey_tasks4,
    setKey_tasks5,
};

int cur_key_gen = 0;

/* Dispatch to current keygen */
void setKey(char *keyBuf, const struct ip* ipHeader, const struct udphdr* udpOrtcpHeader)
{
    memset(keyBuf, 0, KEYLEN);
    key_gens[cur_key_gen](keyBuf, ipHeader, udpOrtcpHeader);
}

#endif
