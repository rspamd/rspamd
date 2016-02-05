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
#ifndef SRC_LIBCRYPTOBOX_KEYPAIR_H_
#define SRC_LIBCRYPTOBOX_KEYPAIR_H_

#include "config.h"
#include "cryptobox.h"
#include "ucl.h"

/**
 * Keypair type
 */
enum rspamd_cryptobox_keypair_type {
	RSPAMD_KEYPAIR_KEX = 0,
	RSPAMD_KEYPAIR_SIGN
};

/**
 * Opaque structure for the full (public + private) keypair
 */
struct rspamd_cryptobox_keypair;
/**
 * Opaque structure for public only keypair
 */
struct rspamd_cryptobox_pubkey;

/**
 * Creates new full keypair
 * @param type type of the keypair
 * @param alg algorithm for the keypair
 * @return fresh keypair generated
 */
struct rspamd_cryptobox_keypair* rspamd_keypair_new (
		enum rspamd_cryptobox_keypair_type type,
		enum rspamd_cryptobox_mode alg);

/**
 * Increase refcount for the specific keypair
 * @param kp
 * @return
 */
struct rspamd_cryptobox_keypair* rspamd_keypair_ref (
		struct rspamd_cryptobox_keypair *kp);

/**
 * Decrease refcount for the specific keypair (or destroy when refcount == 0)
 * @param kp
 */
void rspamd_keypair_unref (struct rspamd_cryptobox_keypair *kp);

/**
 * Increase refcount for the specific pubkey
 * @param kp
 * @return
 */
struct rspamd_cryptobox_pubkey* rspamd_pubkey_ref (
		struct rspamd_cryptobox_pubkey *kp);

/**
 * Load pubkey from base32 string
 * @param b32 input string
 * @param type type of key (signing or kex)
 * @param alg algorithm of the key (nist or curve25519)
 * @return new pubkey or NULL in case of error
 */
struct rspamd_cryptobox_pubkey* rspamd_pubkey_from_base32 (const gchar *b32,
		gsize len,
		enum rspamd_cryptobox_keypair_type type,
		enum rspamd_cryptobox_mode alg);

/**
 * Load pubkey from hex string
 * @param hex input string
 * @param type type of key (signing or kex)
 * @param alg algorithm of the key (nist or curve25519)
 * @return new pubkey or NULL in case of error
 */
struct rspamd_cryptobox_pubkey* rspamd_pubkey_from_hex (const gchar *hex,
		gsize len,
		enum rspamd_cryptobox_keypair_type type,
		enum rspamd_cryptobox_mode alg);


/**
 * Decrease refcount for the specific pubkey (or destroy when refcount == 0)
 * @param kp
 */
void rspamd_pubkey_unref (struct rspamd_cryptobox_pubkey *kp);

/**
 * Get type of keypair
 */
enum rspamd_cryptobox_keypair_type rspamd_keypair_type (
		struct rspamd_cryptobox_keypair *kp);
/**
 * Get type of pubkey
 */
enum rspamd_cryptobox_keypair_type rspamd_pubkey_type (
		struct rspamd_cryptobox_pubkey *p);

/**
 * Get algorithm of keypair
 */
enum rspamd_cryptobox_mode rspamd_keypair_alg (struct rspamd_cryptobox_keypair *kp);
/**
 * Get algorithm of pubkey
 */
enum rspamd_cryptobox_mode rspamd_pubkey_alg (struct rspamd_cryptobox_pubkey *p);

/**
 * Get cached NM for this specific pubkey
 * @param p
 * @return
 */
const guchar * rspamd_pubkey_get_nm (struct rspamd_cryptobox_pubkey *p);


#endif /* SRC_LIBCRYPTOBOX_KEYPAIR_H_ */
