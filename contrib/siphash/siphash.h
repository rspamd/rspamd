/* ==========================================================================
 * siphash.h - SipHash-2-4 in a single header file
 * --------------------------------------------------------------------------
 * Derived by William Ahern from the reference implementation[1] published[2]
 * by Jean-Philippe Aumasson and Daniel J. Berstein. Licensed in kind.
 *
 * 1. https://www.131002.net/siphash/siphash24.c
 * 2. https://www.131002.net/siphash/
 * --------------------------------------------------------------------------
 * HISTORY:
 *
 * 2012-11-04 - Born.
 * --------------------------------------------------------------------------
 * USAGE:
 *
 * SipHash-2-4 takes as input two 64-bit words as the key, some number of
 * message bytes, and outputs a 64-bit word as the message digest. This
 * implementation employs two data structures: a struct sipkey for
 * representing the key, and a struct siphash for representing the hash
 * state.
 *
 * For converting a 16-byte unsigned char array to a key, use either the
 * macro sip_keyof or the routine sip_tokey. The former instantiates a
 * compound literal key, while the latter requires a key object as a
 * parameter.
 *
 * 	unsigned char secret[16];
 * 	arc4random_buf(secret, sizeof secret);
 * 	struct sipkey *key = sip_keyof(secret);
 *
 * For hashing a message, use either the convenience macro siphash24 or the
 * routines sip24_init, sip24_update, and sip24_final.
 *
 * 	struct siphash state;
 * 	void *msg;
 * 	size_t len;
 * 	uint64_t hash;
 *
 * 	sip24_init(&state, key);
 * 	sip24_update(&state, msg, len);
 * 	hash = sip24_final(&state);
 *
 * or
 *
 * 	hash = siphash24(msg, len, key);
 *
 * To convert the 64-bit hash value to a canonical 8-byte little-endian
 * binary representation, use either the macro sip_binof or the routine
 * sip_tobin. The former instantiates and returns a compound literal array,
 * while the latter requires an array object as a parameter.
 * --------------------------------------------------------------------------
 * NOTES:
 *
 * o Neither sip_keyof, sip_binof, nor siphash24 will work with compilers
 *   lacking compound literal support. Instead, you must use the lower-level
 *   interfaces which take as parameters the temporary state objects.
 *
 * o Uppercase macros may evaluate parameters more than once. Lowercase
 *   macros should not exhibit any such side effects.
 * ==========================================================================
 */
#ifndef SIPHASH_H
#define SIPHASH_H

#include <stddef.h> /* size_t */
#include <stdint.h> /* uint64_t uint32_t uint8_t */

#define SIPHASH_INITIALIZER { 0, 0, 0, 0, 0, 0, {{0}} }

struct siphash {
	uint64_t v0, v1, v2, v3;
	uint64_t c;
	unsigned char *p;
	union {
		unsigned char buf[8];
		uint64_t m;
	} b;
}; /* struct siphash */


#define SIP_KEYLEN 16

struct sipkey {
	uint64_t k[2];
}; /* struct sipkey */

struct sipkey *sip_tokey(struct sipkey *key, const void *src);
void *sip_tobin(void *dst, uint64_t u64);
struct siphash *sip24_init(struct siphash *H, const struct sipkey *key);
struct siphash *sip24_update(struct siphash *H, const void *src, size_t len);
uint64_t sip24_final(struct siphash *H);

#define siphash24(src, len, key) \
	sip24_final(sip24_update(sip24_init(&(struct siphash)SIPHASH_INITIALIZER, (key)), (src), (len)))


#endif /* SIPHASH_H */
