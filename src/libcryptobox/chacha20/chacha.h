/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Andrew Moon, Vsevolod Stakhov
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


#ifndef CHACHA_H_
#define CHACHA_H_


#define CHACHA_BLOCKBYTES 64

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct chacha_state_internal_t {
	unsigned char s[48];
	size_t rounds;
	size_t leftover;
	unsigned char buffer[CHACHA_BLOCKBYTES];
} chacha_state_internal;

typedef struct chacha_state_t {
	unsigned char opaque[128];
} chacha_state;

typedef struct chacha_key_t {
	unsigned char b[32];
} chacha_key;

typedef struct chacha_iv_t {
	unsigned char b[8];
} chacha_iv;

typedef struct chacha_iv24_t {
	unsigned char b[24];
} chacha_iv24;

void hchacha (const unsigned char key[32], const unsigned char iv[16],
			  unsigned char out[32], size_t rounds);

void chacha_init (chacha_state *S, const chacha_key *key, const chacha_iv *iv,
				  size_t rounds);

void xchacha_init (chacha_state *S, const chacha_key *key,
				   const chacha_iv24 *iv, size_t rounds);

size_t chacha_update (chacha_state *S, const unsigned char *in,
					  unsigned char *out, size_t inlen);

size_t chacha_final (chacha_state *S, unsigned char *out);

void chacha (const chacha_key *key, const chacha_iv *iv,
			 const unsigned char *in, unsigned char *out, size_t inlen,
			 size_t rounds);

void xchacha (const chacha_key *key, const chacha_iv24 *iv,
			  const unsigned char *in, unsigned char *out, size_t inlen,
			  size_t rounds);

const char *chacha_load (void);

#ifdef  __cplusplus
}
#endif

#endif /* CHACHA_H_ */
