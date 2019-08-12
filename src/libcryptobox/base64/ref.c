/*-
Copyright (c) 2013-2015, Alfred Klomp
Copyright (c) 2016, Vsevolod Stakhov
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

- Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.

- Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "libutil/util.h"

extern const uint8_t base64_table_dec[256];

#define INNER_LOOP_64 do { \
	uint64_t str, res, dec; \
	bool aligned = rspamd_is_aligned_as(c, str); \
	while (inlen >= 13) { \
		if (aligned) { str = *(uint64_t *)c; } else {memcpy(&str, c, sizeof(str)); } \
		str = GUINT64_TO_BE(str); \
		if ((dec = base64_table_dec[str >> 56]) > 63) { \
			break; \
		} \
		res = dec << 58; \
		if ((dec = base64_table_dec[(str >> 48) & 0xFF]) > 63) { \
			break; \
		} \
		res |= dec << 52; \
		if ((dec = base64_table_dec[(str >> 40) & 0xFF]) > 63) { \
			break; \
		} \
		res |= dec << 46; \
		if ((dec = base64_table_dec[(str >> 32) & 0xFF]) > 63) { \
			break; \
		} \
		res |= dec << 40; \
		if ((dec = base64_table_dec[(str >> 24) & 0xFF]) > 63) { \
			break; \
		} \
		res |= dec << 34; \
		if ((dec = base64_table_dec[(str >> 16) & 0xFF]) > 63) { \
			break; \
		} \
		res |= dec << 28; \
		if ((dec = base64_table_dec[(str >> 8) & 0xFF]) > 63) { \
			break; \
		} \
		res |= dec << 22; \
		if ((dec = base64_table_dec[str & 0xFF]) > 63) { \
			break; \
		} \
		res |= dec << 16; \
		res = GUINT64_FROM_BE(res); \
		memcpy(o, &res, sizeof(res)); \
		c += 8; \
		o += 6; \
		outl += 6; \
		inlen -= 8; \
	} \
} while (0)

#define INNER_LOOP_32 do { \
	uint32_t str, res, dec; \
	bool aligned = rspamd_is_aligned_as(c, str); \
	while (inlen >= 8) { \
		if (aligned) { str = *(uint32_t *)c; } else {memcpy(&str, c, sizeof(str)); } \
		str = GUINT32_TO_BE(str); \
		if ((dec = base64_table_dec[str >> 24]) > 63) { \
			break; \
		} \
		res = dec << 26; \
		if ((dec = base64_table_dec[(str >> 16) & 0xFF]) > 63) { \
			break; \
		} \
		res |= dec << 20; \
		if ((dec = base64_table_dec[(str >> 8) & 0xFF]) > 63) { \
			break; \
		} \
		res |= dec << 14; \
		if ((dec = base64_table_dec[str & 0xFF]) > 63) { \
			break; \
		} \
		res |= dec << 8; \
		res = GUINT32_FROM_BE(res); \
		memcpy(o, &res, sizeof(res)); \
		c += 4; \
		o += 3; \
		outl += 3; \
		inlen -= 4; \
	} \
} while (0)


int
base64_decode_ref (const char *in, size_t inlen,
		unsigned char *out, size_t *outlen)
{
	ssize_t ret = 0;
	const uint8_t *c = (const uint8_t *)in;
	uint8_t *o = (uint8_t *)out;
	uint8_t q, carry;
	size_t outl = 0;
	size_t leftover = 0;

repeat:
	switch (leftover) {
		for (;;) {
		case 0:
#if defined(__LP64__)
			INNER_LOOP_64;
#else
			INNER_LOOP_32;
#endif

			if (inlen-- == 0) {
				ret = 1;
				break;
			}
			if ((q = base64_table_dec[*c++]) >= 254) {
				ret = 0;
				break;
			}
			carry = (uint8_t)(q << 2);
			leftover++;

		case 1:
			if (inlen-- == 0) {
				ret = 1;
				break;
			}
			if ((q = base64_table_dec[*c++]) >= 254) {
				ret = 0;
				break;
			}
			*o++ = carry | (q >> 4);
			carry = (uint8_t)(q << 4);
			leftover++;
			outl++;

		case 2:
			if (inlen-- == 0) {
				ret = 1;
				break;
			}
			if ((q = base64_table_dec[*c++]) >= 254) {
				leftover++;

				if (q == 254) {
					if (inlen-- != 0) {
						leftover = 0;
						q = base64_table_dec[*c++];
						ret = ((q == 254) && (inlen == 0)) ? 1 : 0;
						break;
					}
					else {
						ret = 1;
						break;
					}
				}
				else {
					leftover --;
				}
				/* If we get here, there was an error: */
				break;
			}
			*o++ = carry | (q >> 2);
			carry = (uint8_t)(q << 6);
			leftover++;
			outl++;

		case 3:
			if (inlen-- == 0) {
				ret = 1;
				break;
			}
			if ((q = base64_table_dec[*c++]) >= 254) {
				/*
				 * When q == 254, the input char is '='. Return 1 and EOF.
				 * When q == 255, the input char is invalid. Return 0 and EOF.
				 */
				if (q == 254 && inlen == 0) {
					ret = 1;
					leftover = 0;
				}
				else {
					ret = 0;
				}

				break;
			}

			*o++ = carry | q;
			carry = 0;
			leftover = 0;
			outl++;
		}
	}

	if (!ret && inlen > 0) {
		/* Skip to the next valid character in lua_dns_resolver_resolve_commoninput */
		while (inlen > 0 && base64_table_dec[*c] >= 254) {
			c ++;
			inlen --;
		}

		if (inlen > 0) {
			goto repeat;
		}
	}

	*outlen = outl;

	return ret;
}
