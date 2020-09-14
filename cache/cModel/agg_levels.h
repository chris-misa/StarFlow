#ifndef STARFLOW_AGGLEVELS_H
#define STARFLOW_AGGLEVELS_H

#define KEYLEN 13 // Length of key used in any flow tables. 
#define NUM_KEYGENS 2

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

starflow_setKey_t key_gens[NUM_KEYGENS] = {
    setKey_TEST,
    setKey_ORIGINAL
};

int cur_key_gen = 0;

/* Dispatch to current keygen */
void setKey(char *keyBuf, const struct ip* ipHeader, const struct udphdr* udpOrtcpHeader)
{
    key_gens[cur_key_gen](keyBuf, ipHeader, udpOrtcpHeader);
}

#endif
