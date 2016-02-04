/*-
 * Copyright 2016 Vsevolod Stakhov
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
#ifndef RSPAMD_BLAKE2_H
#define RSPAMD_BLAKE2_H

#if defined(__cplusplus)
extern "C" {
#endif

enum blake2b_constant {
	BLAKE2B_BLOCKBYTES = 128,
	BLAKE2B_OUTBYTES = 64,
	BLAKE2B_KEYBYTES = 64,
	BLAKE2B_SALTBYTES = 16,
	BLAKE2B_PERSONALBYTES = 16
};

typedef struct blake2b_state_t {
	unsigned char opaque[256];
} blake2b_state;

/* incremental */
void blake2b_init (blake2b_state *S);

void blake2b_keyed_init (blake2b_state *S,
		const unsigned char *key,
		size_t keylen);

void blake2b_update (blake2b_state *S,
		const unsigned char *in,
		size_t inlen);

void blake2b_final (blake2b_state *S, unsigned char *hash);

/* one-shot */
void blake2b (unsigned char *hash,
		const unsigned char *in,
		size_t inlen);

void blake2b_keyed (unsigned char *hash,
		const unsigned char *in,
		size_t inlen,
		const unsigned char *key,
		size_t keylen);

const char* blake2b_load (void);

#if defined(__cplusplus)
}
#endif

#endif
