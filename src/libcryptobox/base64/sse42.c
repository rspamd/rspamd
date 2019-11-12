/*-
 * Copyright 2017 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
#include "cryptobox.h"

extern const uint8_t base64_table_dec[256];

#ifdef RSPAMD_HAS_TARGET_ATTR
#pragma GCC push_options
#pragma GCC target("sse4.2")
#ifndef __SSE2__
#define __SSE2__
#endif
#ifndef __SSE__
#define __SSE__
#endif
#ifndef __SSE4_2__
#define __SSE4_2__
#endif
#ifndef __SSE4_1__
#define __SSE4_1__
#endif
#ifndef __SSEE3__
#define __SSEE3__
#endif
#include <xmmintrin.h>
#include <nmmintrin.h>


static inline __m128i
dec_reshuffle (__m128i in) __attribute__((__target__("sse4.2")));

static inline __m128i dec_reshuffle (__m128i in)
{
	// Mask in a single byte per shift:
	const __m128i maskB2 = _mm_set1_epi32(0x003F0000);
	const __m128i maskB1 = _mm_set1_epi32(0x00003F00);

	// Pack bytes together:
	__m128i out = _mm_srli_epi32(in, 16);

	out = _mm_or_si128(out, _mm_srli_epi32(_mm_and_si128(in, maskB2), 2));

	out = _mm_or_si128(out, _mm_slli_epi32(_mm_and_si128(in, maskB1), 12));

	out = _mm_or_si128(out, _mm_slli_epi32(in, 26));

	// Reshuffle and repack into 12-byte output format:
	return _mm_shuffle_epi8(out, _mm_setr_epi8(
		 3,  2,  1,
		 7,  6,  5,
		11, 10,  9,
		15, 14, 13,
		-1, -1, -1, -1));
}

#define CMPGT(s,n)	_mm_cmpgt_epi8((s), _mm_set1_epi8(n))

#define INNER_LOOP_SSE42 \
	while (inlen >= 24) { \
		__m128i str = _mm_loadu_si128((__m128i *)c); \
		const __m128i lut = _mm_setr_epi8( \
			19, 16,   4,   4, \
			 4,  4,   4,   4, \
			 4,  4,   4,   4, \
			 0,  0, -71, -65 \
		); \
		const __m128i range = _mm_setr_epi8( \
			'+','+', \
			'+','+', \
			'+','+', \
			'+','+', \
			'/','/', \
			'0','9', \
			'A','Z', \
			'a','z'); \
		if (_mm_cmpistrc(range, str, _SIDD_UBYTE_OPS | _SIDD_CMP_RANGES | _SIDD_NEGATIVE_POLARITY)) { \
			seen_error = true; \
			break; \
		} \
		__m128i indices = _mm_subs_epu8(str, _mm_set1_epi8(46)); \
		__m128i mask45 = CMPGT(str, 64); \
		__m128i mask5  = CMPGT(str, 96); \
		indices = _mm_andnot_si128(mask45, indices); \
		mask45 = _mm_add_epi8(_mm_slli_epi16(_mm_abs_epi8(mask45), 4), mask45); \
		indices = _mm_add_epi8(indices, mask45); \
		indices = _mm_add_epi8(indices, mask5); \
		__m128i delta = _mm_shuffle_epi8(lut, indices); \
		str = _mm_add_epi8(str, delta); \
		str = dec_reshuffle(str); \
		_mm_storeu_si128((__m128i *)o, str); \
		c += 16; \
		o += 12; \
		outl += 12; \
		inlen -= 16; \
	}

int
base64_decode_sse42 (const char *in, size_t inlen,
		unsigned char *out, size_t *outlen) __attribute__((__target__("sse4.2")));
int
base64_decode_sse42 (const char *in, size_t inlen,
		unsigned char *out, size_t *outlen)
{
	ssize_t ret = 0;
	const uint8_t *c = (const uint8_t *)in;
	uint8_t *o = (uint8_t *)out;
	uint8_t q, carry;
	size_t outl = 0;
	size_t leftover = 0;
	bool seen_error = false;

repeat:
	switch (leftover) {
		for (;;) {
		case 0:
			if (G_LIKELY (!seen_error)) {
				INNER_LOOP_SSE42
			}

			if (inlen-- == 0) {
				ret = 1;
				break;
			}
			if ((q = base64_table_dec[*c++]) >= 254) {
				ret = 0;
				break;
			}
			carry = q << 2;
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
			carry = q << 4;
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
			carry = q << 6;
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
		/* Skip to the next valid character in input */
		while (inlen > 0 && base64_table_dec[*c] >= 254) {
			c ++;
			inlen --;
		}

		if (inlen > 0) {
			seen_error = false;
			goto repeat;
		}
	}

	*outlen = outl;

	return ret;
}

#pragma GCC pop_options
#endif
