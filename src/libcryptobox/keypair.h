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

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Keypair type
 */
enum rspamd_cryptobox_keypair_type {
	RSPAMD_KEYPAIR_KEX = 0,
	RSPAMD_KEYPAIR_SIGN
};

extern const guchar encrypted_magic[7];

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
struct rspamd_cryptobox_keypair *rspamd_keypair_new (
		enum rspamd_cryptobox_keypair_type type,
		enum rspamd_cryptobox_mode alg);

/**
 * Increase refcount for the specific keypair
 * @param kp
 * @return
 */
struct rspamd_cryptobox_keypair *rspamd_keypair_ref (
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
struct rspamd_cryptobox_pubkey *rspamd_pubkey_ref (
		struct rspamd_cryptobox_pubkey *kp);

/**
 * Load pubkey from base32 string
 * @param b32 input string
 * @param type type of key (signing or kex)
 * @param alg algorithm of the key (nist or curve25519)
 * @return new pubkey or NULL in case of error
 */
struct rspamd_cryptobox_pubkey *rspamd_pubkey_from_base32 (const gchar *b32,
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
struct rspamd_cryptobox_pubkey *rspamd_pubkey_from_hex (const gchar *hex,
														gsize len,
														enum rspamd_cryptobox_keypair_type type,
														enum rspamd_cryptobox_mode alg);

/**
 * Load pubkey from raw chunk string
 * @param hex input data
 * @param type type of key (signing or kex)
 * @param alg algorithm of the key (nist or curve25519)
 * @return new pubkey or NULL in case of error
 */
struct rspamd_cryptobox_pubkey *rspamd_pubkey_from_bin (const guchar *raw,
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
const guchar *rspamd_pubkey_get_nm (struct rspamd_cryptobox_pubkey *p,
									struct rspamd_cryptobox_keypair *kp);

/**
 * Calculate and store nm value for the specified local key (performs ECDH)
 * @param p
 * @return
 */
const guchar *rspamd_pubkey_calculate_nm (struct rspamd_cryptobox_pubkey *p,
										  struct rspamd_cryptobox_keypair *kp);

/**
 * Get raw public key id for a specified keypair (rspamd_cryptobox_HASHBYTES)
 * @param kp
 * @return
 */
const guchar *rspamd_keypair_get_id (struct rspamd_cryptobox_keypair *kp);

/**
 * Get raw public key id for a specified key (rspamd_cryptobox_HASHBYTES)
 * @param kp
 * @return
 */
const guchar *rspamd_pubkey_get_id (struct rspamd_cryptobox_pubkey *pk);

/**
 * Get raw public key from pubkey opaque structure
 * @param pk
 * @param len
 * @return
 */
const guchar *rspamd_pubkey_get_pk (struct rspamd_cryptobox_pubkey *pk,
									guint *len);

/** Short ID characters count */
#define RSPAMD_KEYPAIR_SHORT_ID_LEN 5
/** Print pubkey */
#define RSPAMD_KEYPAIR_PUBKEY 0x1
/** Print secret key */
#define RSPAMD_KEYPAIR_PRIVKEY 0x2
/** Print key id */
#define RSPAMD_KEYPAIR_ID 0x4
/** Print short key id */
#define RSPAMD_KEYPAIR_ID_SHORT 0x8
/** Encode output with base 32 */
#define RSPAMD_KEYPAIR_BASE32 0x10
/** Human readable output */
#define RSPAMD_KEYPAIR_HUMAN 0x20
#define RSPAMD_KEYPAIR_HEX 0x40

/**
 * Print keypair encoding it if needed
 * @param key key to print
 * @param how flags that specifies printing behaviour
 * @return newly allocated string with keypair
 */
GString *rspamd_keypair_print (struct rspamd_cryptobox_keypair *kp,
							   guint how);

/**
 * Print pubkey encoding it if needed
 * @param key key to print
 * @param how flags that specifies printing behaviour
 * @return newly allocated string with keypair
 */
GString *rspamd_pubkey_print (struct rspamd_cryptobox_pubkey *pk,
							  guint how);

/** Get keypair pubkey ID */
#define RSPAMD_KEYPAIR_COMPONENT_ID 0
/** Get keypair public key */
#define RSPAMD_KEYPAIR_COMPONENT_PK 1
/** Get keypair private key */
#define RSPAMD_KEYPAIR_COMPONENT_SK 2

/**
 * Get specific component of a keypair
 * @param kp keypair
 * @param ncomp component number
 * @param len length of input
 * @return raw content of the component
 */
const guchar *rspamd_keypair_component (struct rspamd_cryptobox_keypair *kp,
										guint ncomp, guint *len);

/**
 * Create a new keypair from ucl object
 * @param obj object to load
 * @return new structure or NULL if an object is invalid
 */
struct rspamd_cryptobox_keypair *rspamd_keypair_from_ucl (const ucl_object_t *obj);

/**
 * Converts keypair to ucl object
 * @param kp
 * @return
 */
ucl_object_t *rspamd_keypair_to_ucl (struct rspamd_cryptobox_keypair *kp,
									 gboolean is_hex);

/**
 * Signs memory using the specified keypair
 * @param kp keypair
 * @param data data to sign
 * @param data to sign
 * @param sig output signature (allocated by function, must be freed by a callee)
 * @param outlen length of output data
 * @param err filled if function returns `FALSE`
 * @return TRUE if signature operation succeeded
 */
gboolean rspamd_keypair_sign (struct rspamd_cryptobox_keypair *kp,
							  const void *data, gsize len, guchar **sig, gsize *outlen,
							  GError **err);

/***
 * Verifies data using public key
 * @param pk public key
 * @param data data to sign
 * @param len data to sign
 * @param sig signature to verify
 * @param siglen length of signature
 * @param err filled if function returns `FALSE`
 * @return TRUE if signature is valid
 */
gboolean rspamd_keypair_verify (struct rspamd_cryptobox_pubkey *pk,
								const void *data, gsize len, const guchar *sig, gsize siglen,
								GError **err);

/**
 * Compares two public keys
 * @param k1 key to compare
 * @param k2 key to compare
 * @return TRUE if two keys are equal
 */
gboolean rspamd_pubkey_equal (const struct rspamd_cryptobox_pubkey *k1,
							  const struct rspamd_cryptobox_pubkey *k2);

/**
 * Decrypts data using keypair and a pubkey stored in in, in must start from
 * `encrypted_magic` constant
 * @param kp keypair
 * @param in raw input
 * @param inlen input length
 * @param out output (allocated internally using g_malloc)
 * @param outlen output size
 * @return TRUE if decryption is completed, out must be freed in this case
 */
gboolean rspamd_keypair_decrypt (struct rspamd_cryptobox_keypair *kp,
								 const guchar *in, gsize inlen,
								 guchar **out, gsize *outlen,
								 GError **err);

/**
 * Encrypts data usign specific keypair.
 * This method actually generates ephemeral local keypair, use public key from
 * the remote keypair and encrypts data
 * @param kp keypair
 * @param in raw input
 * @param inlen input length
 * @param out output (allocated internally using g_malloc)
 * @param outlen output size
 * @param err pointer to error
 * @return TRUE if encryption has been completed, out must be freed in this case
 */
gboolean rspamd_keypair_encrypt (struct rspamd_cryptobox_keypair *kp,
								 const guchar *in, gsize inlen,
								 guchar **out, gsize *outlen,
								 GError **err);

/**
 * Encrypts data usign specific pubkey (must have KEX type).
 * This method actually generates ephemeral local keypair, use public key from
 * the remote keypair and encrypts data
 * @param kp keypair
 * @param in raw input
 * @param inlen input length
 * @param out output (allocated internally using g_malloc)
 * @param outlen output size
 * @param err pointer to error
 * @return TRUE if encryption has been completed, out must be freed in this case
 */
gboolean rspamd_pubkey_encrypt (struct rspamd_cryptobox_pubkey *pk,
								const guchar *in, gsize inlen,
								guchar **out, gsize *outlen,
								GError **err);

#ifdef  __cplusplus
}
#endif

#endif /* SRC_LIBCRYPTOBOX_KEYPAIR_H_ */
