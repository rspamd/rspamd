/*
 * Copyright 2024 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CRYPTOBOX_H_
#define CRYPTOBOX_H_

#include "config.h"

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#endif

#include <sodium.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rspamd_cryptobox_segment {
	unsigned char *data;
	gsize len;
};

#if defined(__GNUC__) &&                                                                                 \
	((defined(__clang__) && (__clang_major__ >= 4 || (__clang_major__ >= 3 && __clang_minor__ >= 8))) || \
	 ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 8) || (__GNUC__ > 4)))
#define RSPAMD_HAS_TARGET_ATTR 1
#endif

#define rspamd_cryptobox_MAX_NONCEBYTES 24
#define rspamd_cryptobox_MAX_PKBYTES 65
#define rspamd_cryptobox_MAX_SKBYTES 32
#define rspamd_cryptobox_MAX_MACBYTES 16
#define rspamd_cryptobox_MAX_NMBYTES 32
#define rspamd_cryptobox_SIPKEYBYTES 16
#define rspamd_cryptobox_HASHBYTES 64
#define rspamd_cryptobox_HASHKEYBYTES 64
#define rspamd_cryptobox_HASHSTATEBYTES sizeof(crypto_generichash_blake2b_state) + 64
#define rspamd_cryptobox_MAX_SIGSKBYTES 64
#define rspamd_cryptobox_MAX_SIGPKBYTES 65
#define rspamd_cryptobox_MAX_SIGBYTES 72

#define CPUID_AVX2 0x1
#define CPUID_AVX 0x2
#define CPUID_SSE2 0x4
#define CPUID_SSE3 0x8
#define CPUID_SSSE3 0x10
#define CPUID_SSE41 0x20
#define CPUID_SSE42 0x40
#define CPUID_RDRAND 0x80

typedef unsigned char rspamd_pk_t[rspamd_cryptobox_MAX_PKBYTES];
typedef unsigned char rspamd_sk_t[rspamd_cryptobox_MAX_SKBYTES];
typedef unsigned char rspamd_mac_t[rspamd_cryptobox_MAX_MACBYTES];
typedef unsigned char rspamd_nm_t[rspamd_cryptobox_MAX_NMBYTES];
typedef unsigned char rspamd_nonce_t[rspamd_cryptobox_MAX_NONCEBYTES];
typedef unsigned char rspamd_sipkey_t[rspamd_cryptobox_SIPKEYBYTES];
typedef unsigned char rspamd_signature_t[rspamd_cryptobox_MAX_SIGBYTES];
typedef unsigned char rspamd_sig_pk_t[rspamd_cryptobox_MAX_SIGPKBYTES];
typedef unsigned char rspamd_sig_sk_t[rspamd_cryptobox_MAX_SIGSKBYTES];

enum rspamd_cryptobox_mode {
	RSPAMD_CRYPTOBOX_MODE_25519 = 0,
	RSPAMD_CRYPTOBOX_MODE_NIST
};

struct rspamd_cryptobox_library_ctx {
	char *cpu_extensions;
	const char *chacha20_impl;
	const char *base64_impl;
	unsigned long cpu_config;
};

/**
* Init cryptobox library
*/
struct rspamd_cryptobox_library_ctx *rspamd_cryptobox_init(void);

void rspamd_cryptobox_deinit(struct rspamd_cryptobox_library_ctx *);
/**
* Generate new keypair
* @param pk public key buffer
* @param sk secret key buffer
*/
void rspamd_cryptobox_keypair(rspamd_pk_t pk, rspamd_sk_t sk,
							  enum rspamd_cryptobox_mode mode);

/**
* Generate new keypair for signing
* @param pk public key buffer
* @param sk secret key buffer
*/
void rspamd_cryptobox_keypair_sig(rspamd_sig_pk_t pk, rspamd_sig_sk_t sk,
								  enum rspamd_cryptobox_mode mode);

/**
* Encrypt data inplace adding signature to sig afterwards
* @param data input buffer
* @param pk remote pubkey
* @param sk local secret key
* @param sig output signature
*/
void rspamd_cryptobox_encrypt_inplace(unsigned char *data, gsize len,
									  const rspamd_nonce_t nonce,
									  const rspamd_pk_t pk, const rspamd_sk_t sk, rspamd_mac_t sig,
									  enum rspamd_cryptobox_mode mode);

/**
* Encrypt segments of data inplace adding signature to sig afterwards
* @param segments segments of data
* @param cnt count of segments
* @param pk remote pubkey
* @param sk local secret key
* @param sig output signature
*/
void rspamd_cryptobox_encryptv_inplace(struct rspamd_cryptobox_segment *segments,
									   gsize cnt,
									   const rspamd_nonce_t nonce,
									   const rspamd_pk_t pk, const rspamd_sk_t sk, rspamd_mac_t sig,
									   enum rspamd_cryptobox_mode mode);


/**
* Decrypt and verify data chunk inplace
* @param data data to decrypt
* @param len length of data
* @param pk remote pubkey
* @param sk local privkey
* @param sig signature input
* @return TRUE if input has been verified successfully
*/
gboolean rspamd_cryptobox_decrypt_inplace(unsigned char *data, gsize len,
										  const rspamd_nonce_t nonce,
										  const rspamd_pk_t pk, const rspamd_sk_t sk, const rspamd_mac_t sig,
										  enum rspamd_cryptobox_mode mode);

/**
* Encrypt segments of data inplace adding signature to sig afterwards
* @param segments segments of data
* @param cnt count of segments
* @param pk remote pubkey
* @param sk local secret key
* @param sig output signature
*/
void rspamd_cryptobox_encrypt_nm_inplace(unsigned char *data, gsize len,
										 const rspamd_nonce_t nonce,
										 const rspamd_nm_t nm, rspamd_mac_t sig,
										 enum rspamd_cryptobox_mode mode);

/**
* Encrypt segments of data inplace adding signature to sig afterwards
* @param segments segments of data
* @param cnt count of segments
* @param pk remote pubkey
* @param sk local secret key
* @param sig output signature
*/
void rspamd_cryptobox_encryptv_nm_inplace(struct rspamd_cryptobox_segment *segments,
										  gsize cnt,
										  const rspamd_nonce_t nonce,
										  const rspamd_nm_t nm, rspamd_mac_t sig,
										  enum rspamd_cryptobox_mode mode);


/**
* Decrypt and verify data chunk inplace
* @param data data to decrypt
* @param len length of data
* @param pk remote pubkey
* @param sk local privkey
* @param sig signature input
* @return TRUE if input has been verified successfully
*/
gboolean rspamd_cryptobox_decrypt_nm_inplace(unsigned char *data, gsize len,
											 const rspamd_nonce_t nonce,
											 const rspamd_nm_t nm, const rspamd_mac_t sig,
											 enum rspamd_cryptobox_mode mode);

/**
* Generate shared secret from local sk and remote pk
* @param nm shared secret
* @param pk remote pubkey
* @param sk local privkey
*/
void rspamd_cryptobox_nm(rspamd_nm_t nm, const rspamd_pk_t pk,
						 const rspamd_sk_t sk, enum rspamd_cryptobox_mode mode);

/**
* Create digital signature for the specified message and place result in `sig`
* @param sig signature target
* @param siglen_p pointer to signature length (might be NULL)
* @param m input message
* @param mlen input length
* @param sk secret key
*/
void rspamd_cryptobox_sign(unsigned char *sig, unsigned long long *siglen_p,
						   const unsigned char *m, gsize mlen,
						   const rspamd_sk_t sk,
						   enum rspamd_cryptobox_mode mode);

/**
* Verifies digital signature for the specified message using the specified
* pubkey
* @param sig signature source
* @param m input message
* @param mlen message length
* @param pk public key for verification
* @return true if signature is valid, false otherwise
*/
bool rspamd_cryptobox_verify(const unsigned char *sig,
							 gsize siglen,
							 const unsigned char *m,
							 gsize mlen,
							 const rspamd_pk_t pk,
							 enum rspamd_cryptobox_mode mode);

#ifdef HAVE_OPENSSL
/**
 * Verifies digital signature for specified raw digest with specified pubkey
 * @param nid signing algorithm nid
 * @param sig signature source
 * @param digest raw digest
 * @param pub_key public key for verification
 * @return true if signature is valid, false otherwise
 */
bool rspamd_cryptobox_verify_evp_ed25519(int nid,
										 const unsigned char *sig,
										 gsize siglen,
										 const unsigned char *digest,
										 gsize dlen,
										 EVP_PKEY *pub_key);
bool rspamd_cryptobox_verify_evp_ecdsa(int nid,
									   const unsigned char *sig,
									   gsize siglen,
									   const unsigned char *digest,
									   gsize dlen,
									   EVP_PKEY *pub_key);
bool rspamd_cryptobox_verify_evp_rsa(int nid,
									 const unsigned char *sig,
									 gsize siglen,
									 const unsigned char *digest,
									 gsize dlen,
									 EVP_PKEY *pub_key);
#endif

/**
* Securely clear the buffer specified
* @param buf buffer to zero
* @param buflen length of buffer
*/

#define rspamd_explicit_memzero sodium_memzero

/**
* Constant time memcmp
* @param b1_
* @param b2_
* @param len
* @return
*/
#define rspamd_cryptobox_memcmp sodium_memcmp

/**
* Calculates siphash-2-4 for a message
* @param out (8 bytes output)
* @param in
* @param inlen
* @param k key (must be 16 bytes)
*/
void rspamd_cryptobox_siphash(unsigned char *out, const unsigned char *in,
							  unsigned long long inlen,
							  const rspamd_sipkey_t k);

enum rspamd_cryptobox_pbkdf_type {
	RSPAMD_CRYPTOBOX_PBKDF2 = 0,
	RSPAMD_CRYPTOBOX_CATENA
};


/**
* Derive key from password using the specified algorithm
* @param pass input password
* @param pass_len length of the password
* @param salt input salt
* @param salt_len length of salt
* @param key output key
* @param key_len size of the key
* @param complexity empiric number of complexity (rounds for pbkdf2 and garlic for catena)
* @return TRUE in case of success and FALSE if failed
*/
gboolean rspamd_cryptobox_pbkdf(const char *pass, gsize pass_len,
								const uint8_t *salt, gsize salt_len,
								uint8_t *key, gsize key_len,
								unsigned int complexity,
								enum rspamd_cryptobox_pbkdf_type type);


/**
* Real size of rspamd cryptobox public key
*/
unsigned int rspamd_cryptobox_pk_bytes(enum rspamd_cryptobox_mode mode);

/**
* Real size of rspamd cryptobox signing public key
*/
unsigned int rspamd_cryptobox_pk_sig_bytes(enum rspamd_cryptobox_mode mode);

/**
* Real size of crypto nonce
*/
unsigned int rspamd_cryptobox_nonce_bytes(enum rspamd_cryptobox_mode mode);

/**
* Real size of rspamd cryptobox secret key
*/
unsigned int rspamd_cryptobox_sk_bytes(enum rspamd_cryptobox_mode mode);

/**
* Real size of rspamd cryptobox signing secret key
*/
unsigned int rspamd_cryptobox_sk_sig_bytes(enum rspamd_cryptobox_mode mode);

/**
* Real size of rspamd cryptobox shared key
*/
unsigned int rspamd_cryptobox_nm_bytes(enum rspamd_cryptobox_mode mode);

/**
* Real size of rspamd cryptobox MAC signature
*/
unsigned int rspamd_cryptobox_mac_bytes(enum rspamd_cryptobox_mode mode);

/**
* Real size of rspamd cryptobox digital signature
*/
unsigned int rspamd_cryptobox_signature_bytes(enum rspamd_cryptobox_mode mode);

/* Hash IUF interface */
typedef crypto_generichash_blake2b_state rspamd_cryptobox_hash_state_t;

/**
* Init cryptobox hash state using key if needed, `st` must point to the buffer
* with at least rspamd_cryptobox_HASHSTATEBYTES bytes length. If keylen == 0, then
* non-keyed hash is generated
*/
void rspamd_cryptobox_hash_init(rspamd_cryptobox_hash_state_t *st,
								const unsigned char *key, gsize keylen);

/**
* Update hash with data portion
*/
void rspamd_cryptobox_hash_update(rspamd_cryptobox_hash_state_t *st,
								  const unsigned char *data, gsize len);

/**
* Output hash to the buffer of rspamd_cryptobox_HASHBYTES length
*/
void rspamd_cryptobox_hash_final(rspamd_cryptobox_hash_state_t *st, unsigned char *out);

/**
* One in all function
*/
void rspamd_cryptobox_hash(unsigned char *out,
						   const unsigned char *data,
						   gsize len,
						   const unsigned char *key,
						   gsize keylen);

enum rspamd_cryptobox_fast_hash_type {
	RSPAMD_CRYPTOBOX_XXHASH64 = 0,
	RSPAMD_CRYPTOBOX_XXHASH32,
	RSPAMD_CRYPTOBOX_XXHASH3,
	RSPAMD_CRYPTOBOX_MUMHASH,
	RSPAMD_CRYPTOBOX_T1HA,
	RSPAMD_CRYPTOBOX_HASHFAST,
	RSPAMD_CRYPTOBOX_HASHFAST_INDEPENDENT
};

/* Non crypto hash IUF interface */
typedef struct CRYPTO_ALIGN(64) rspamd_cryptobox_fast_hash_state_s {
	unsigned char opaque[576]; /* Required for xxhash3 */
	enum rspamd_cryptobox_fast_hash_type type;
} rspamd_cryptobox_fast_hash_state_t;


/**
* Creates a new cryptobox state properly aligned
* @return
*/
rspamd_cryptobox_fast_hash_state_t *rspamd_cryptobox_fast_hash_new(void);
void rspamd_cryptobox_fast_hash_free(rspamd_cryptobox_fast_hash_state_t *st);

/**
* Init cryptobox hash state using key if needed, `st` must point to the buffer
* with at least rspamd_cryptobox_HASHSTATEBYTES bytes length. If keylen == 0, then
* non-keyed hash is generated
*/
void rspamd_cryptobox_fast_hash_init(rspamd_cryptobox_fast_hash_state_t *st,
									 uint64_t seed);

/**
* Init cryptobox hash state using key if needed, `st` must point to the buffer
* with at least rspamd_cryptobox_HASHSTATEBYTES bytes length. If keylen == 0, then
* non-keyed hash is generated
*/
void rspamd_cryptobox_fast_hash_init_specific(rspamd_cryptobox_fast_hash_state_t *st,
											  enum rspamd_cryptobox_fast_hash_type type,
											  uint64_t seed);

/**
* Update hash with data portion
*/
void rspamd_cryptobox_fast_hash_update(rspamd_cryptobox_fast_hash_state_t *st,
									   const void *data, gsize len);

/**
* Output hash to the buffer of rspamd_cryptobox_HASHBYTES length
*/
uint64_t rspamd_cryptobox_fast_hash_final(rspamd_cryptobox_fast_hash_state_t *st);

/**
* One in all function
*/
uint64_t rspamd_cryptobox_fast_hash(const void *data,
									gsize len, uint64_t seed);

/**
* Platform independent version
*/
uint64_t rspamd_cryptobox_fast_hash_specific(
	enum rspamd_cryptobox_fast_hash_type type,
	const void *data,
	gsize len, uint64_t seed);

/**
* Decode base64 using platform optimized code
* @param in
* @param inlen
* @param out
* @param outlen
* @return
*/
gboolean rspamd_cryptobox_base64_decode(const char *in, gsize inlen,
										unsigned char *out, gsize *outlen);

/**
* Returns TRUE if data looks like a valid base64 string
* @param in
* @param inlen
* @return
*/
gboolean rspamd_cryptobox_base64_is_valid(const char *in, gsize inlen);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTOBOX_H_ */
