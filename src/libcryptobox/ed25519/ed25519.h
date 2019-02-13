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
#ifndef SRC_LIBCRYPTOBOX_ED25519_ED25519_H_
#define SRC_LIBCRYPTOBOX_ED25519_ED25519_H_

#include "config.h"
#include <stdbool.h>
#include <stddef.h>

const char* ed25519_load (void);
void ed25519_keypair (unsigned char *pk, unsigned char *sk);
void ed25519_seed_keypair (unsigned char *pk, unsigned char *sk, unsigned char *seed);
void ed25519_sign (unsigned char *sig, size_t *siglen_p,
		const unsigned char *m, size_t mlen,
		const unsigned char *sk);
bool ed25519_verify (const unsigned char *sig,
		const unsigned char *m,
		size_t mlen,
		const unsigned char *pk);

#endif /* SRC_LIBCRYPTOBOX_ED25519_ED25519_H_ */
