/*-
 * Copyright 2018 Vsevolod Stakhov
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
Copyright (c) 2018, Vsevolod Stakhov
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
#pragma GCC target("avx2")
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
#ifndef __AVX__
#define __AVX__
#endif
#ifndef __AVX2__
#define __AVX2__
#endif

#include <immintrin.h>

#define CMPGT(s,n)	_mm256_cmpgt_epi8((s), _mm256_set1_epi8(n))
#define CMPEQ(s,n)	_mm256_cmpeq_epi8((s), _mm256_set1_epi8(n))
#define REPLACE(s,n)	_mm256_and_si256((s), _mm256_set1_epi8(n))
#define RANGE(s,a,b)	_mm256_andnot_si256(CMPGT((s), (b)), CMPGT((s), (a) - 1))

static inline __m256i
dec_reshuffle (__m256i in) __attribute__((__target__("avx2")));

static inline __m256i
dec_reshuffle (__m256i in)
{
	// in, lower lane, bits, upper case are most significant bits, lower case are least significant bits:
	// 00llllll 00kkkkLL 00jjKKKK 00JJJJJJ
	// 00iiiiii 00hhhhII 00ggHHHH 00GGGGGG
	// 00ffffff 00eeeeFF 00ddEEEE 00DDDDDD
	// 00cccccc 00bbbbCC 00aaBBBB 00AAAAAA

	const __m256i merge_ab_and_bc = _mm256_maddubs_epi16(in, _mm256_set1_epi32(0x01400140));
	// 0000kkkk LLllllll 0000JJJJ JJjjKKKK
	// 0000hhhh IIiiiiii 0000GGGG GGggHHHH
	// 0000eeee FFffffff 0000DDDD DDddEEEE
	// 0000bbbb CCcccccc 0000AAAA AAaaBBBB

	__m256i out = _mm256_madd_epi16(merge_ab_and_bc, _mm256_set1_epi32(0x00011000));
	// 00000000 JJJJJJjj KKKKkkkk LLllllll
	// 00000000 GGGGGGgg HHHHhhhh IIiiiiii
	// 00000000 DDDDDDdd EEEEeeee FFffffff
	// 00000000 AAAAAAaa BBBBbbbb CCcccccc

	// Pack bytes together in each lane:
	out = _mm256_shuffle_epi8(out, _mm256_setr_epi8(
		2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1,
		2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1));
	// 00000000 00000000 00000000 00000000
	// LLllllll KKKKkkkk JJJJJJjj IIiiiiii
	// HHHHhhhh GGGGGGgg FFffffff EEEEeeee
	// DDDDDDdd CCcccccc BBBBbbbb AAAAAAaa

	// Pack lanes
	return _mm256_permutevar8x32_epi32(out, _mm256_setr_epi32(0, 1, 2, 4, 5, 6, -1, -1));
}


#define INNER_LOOP_AVX2 \
	while (inlen >= 45) { \
		__m256i str = _mm256_loadu_si256((__m256i *)c); \
		const __m256i lut_lo = _mm256_setr_epi8( \
			0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, \
			0x11, 0x11, 0x13, 0x1A, 0x1B, 0x1B, 0x1B, 0x1A, \
			0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, \
			0x11, 0x11, 0x13, 0x1A, 0x1B, 0x1B, 0x1B, 0x1A); \
		const __m256i lut_hi = _mm256_setr_epi8( \
			0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08, \
			0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, \
			0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08, \
			0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10); \
		const __m256i lut_roll = _mm256_setr_epi8( \
			0,  16,  19,   4, -65, -65, -71, -71, \
			0,   0,   0,   0,   0,   0,   0,   0, \
			0,  16,  19,   4, -65, -65, -71, -71, \
			0,   0,   0,   0,   0,   0,   0,   0); \
		const __m256i mask_2F = _mm256_set1_epi8(0x2f); \
		const __m256i hi_nibbles  = _mm256_and_si256(_mm256_srli_epi32(str, 4), mask_2F); \
		const __m256i lo_nibbles  = _mm256_and_si256(str, mask_2F); \
		const __m256i hi          = _mm256_shuffle_epi8(lut_hi, hi_nibbles); \
		const __m256i lo          = _mm256_shuffle_epi8(lut_lo, lo_nibbles); \
		const __m256i eq_2F       = _mm256_cmpeq_epi8(str, mask_2F); \
		const __m256i roll        = _mm256_shuffle_epi8(lut_roll, _mm256_add_epi8(eq_2F, hi_nibbles)); \
		if (!_mm256_testz_si256(lo, hi)) { \
			seen_error = true; \
			break; \
		} \
		str = _mm256_add_epi8(str, roll); \
		str = dec_reshuffle(str); \
		_mm256_storeu_si256((__m256i *)o, str); \
		c += 32; \
		o += 24; \
		outl += 24; \
		inlen -= 32; \
	}

int
base64_decode_avx2 (const char *in, size_t inlen,
		unsigned char *out, size_t *outlen) __attribute__((__target__("avx2")));
int
base64_decode_avx2 (const char *in, size_t inlen,
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
				INNER_LOOP_AVX2
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
