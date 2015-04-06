#ifndef SIPHASH_INTERNAL_H
#define SIPHASH_INTERNAL_H

#include <endian.h>
#define SIP_ROTL(x, b) (uint64_t)(((x) << (b)) | ( (x) >> (64 - (b))))

#define SIP_U32TO8_LE(p, v) \
	(p)[0] = (uint8_t)((v) >>  0); (p)[1] = (uint8_t)((v) >>  8); \
	(p)[2] = (uint8_t)((v) >> 16); (p)[3] = (uint8_t)((v) >> 24);

#define SIP_U64TO8_LE(p, v) \
	SIP_U32TO8_LE((p) + 0, (uint32_t)((v) >>  0)); \
	SIP_U32TO8_LE((p) + 4, (uint32_t)((v) >> 32));

#if BYTE_ORDER != LITTLE_ENDIAN
#define SIP_U8TO64_LE(p) \
	(((uint64_t)((p)[0]) <<  0) | \
	 ((uint64_t)((p)[1]) <<  8) | \
	 ((uint64_t)((p)[2]) << 16) | \
	 ((uint64_t)((p)[3]) << 24) | \
	 ((uint64_t)((p)[4]) << 32) | \
	 ((uint64_t)((p)[5]) << 40) | \
	 ((uint64_t)((p)[6]) << 48) | \
	 ((uint64_t)((p)[7]) << 56))
#else
#define SIP_U8TO64_LE(p) (*(uint64_t*)(p))
#endif

#define sip_keyof(k) sip_tokey(&(struct sipkey){ { 0 } }, (k))

#define sip_binof(v) sip_tobin((unsigned char[8]){ 0 }, (v))

#define sip_endof(a) (&(a)[sizeof (a) / sizeof *(a)])

#endif /* SIPHASH_INTERNAL_H */
