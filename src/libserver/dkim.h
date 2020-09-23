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
#ifndef DKIM_H_
#define DKIM_H_

#include "config.h"
#include "contrib/libev/ev.h"
#include "dns.h"
#include "ref.h"


/* Main types and definitions */

#define RSPAMD_DKIM_SIGNHEADER     "DKIM-Signature"
#define RSPAMD_DKIM_ARC_SIGNHEADER     "ARC-Message-Signature"
#define RSPAMD_DKIM_ARC_AUTHHEADER     "ARC-Authentication-Results"
#define RSPAMD_DKIM_ARC_SEALHEADER     "ARC-Seal"
/* DKIM signature header */


/* Errors (from OpenDKIM) */

#define DKIM_SIGERROR_UNKNOWN       (-1)    /* unknown error */
#define DKIM_SIGERROR_OK        0   /* no error */
#define DKIM_SIGERROR_VERSION       1   /* unsupported version */
#define DKIM_SIGERROR_DOMAIN        2   /* invalid domain (d=/i=) */
#define DKIM_SIGERROR_EXPIRED       3   /* signature expired */
#define DKIM_SIGERROR_FUTURE        4   /* signature in the future */
#define DKIM_SIGERROR_TIMESTAMPS    5   /* x= < t= */
#define DKIM_SIGERROR_NOREC         6   /* No record */
#define DKIM_SIGERROR_INVALID_HC    7   /* c= invalid (header) */
#define DKIM_SIGERROR_INVALID_BC    8   /* c= invalid (body) */
#define DKIM_SIGERROR_MISSING_A     9   /* a= missing */
#define DKIM_SIGERROR_INVALID_A     10  /* a= invalid */
#define DKIM_SIGERROR_MISSING_H     11  /* h= missing */
#define DKIM_SIGERROR_INVALID_L     12  /* l= invalid */
#define DKIM_SIGERROR_INVALID_Q     13  /* q= invalid */
#define DKIM_SIGERROR_INVALID_QO    14  /* q= option invalid */
#define DKIM_SIGERROR_MISSING_D     15  /* d= missing */
#define DKIM_SIGERROR_EMPTY_D       16  /* d= empty */
#define DKIM_SIGERROR_MISSING_S     17  /* s= missing */
#define DKIM_SIGERROR_EMPTY_S       18  /* s= empty */
#define DKIM_SIGERROR_MISSING_B     19  /* b= missing */
#define DKIM_SIGERROR_EMPTY_B       20  /* b= empty */
#define DKIM_SIGERROR_CORRUPT_B     21  /* b= corrupt */
#define DKIM_SIGERROR_NOKEY     22  /* no key found in DNS */
#define DKIM_SIGERROR_DNSSYNTAX     23  /* DNS reply corrupt */
#define DKIM_SIGERROR_KEYFAIL       24  /* DNS query failed */
#define DKIM_SIGERROR_MISSING_BH    25  /* bh= missing */
#define DKIM_SIGERROR_EMPTY_BH      26  /* bh= empty */
#define DKIM_SIGERROR_CORRUPT_BH    27  /* bh= corrupt */
#define DKIM_SIGERROR_BADSIG        28  /* signature mismatch */
#define DKIM_SIGERROR_SUBDOMAIN     29  /* unauthorized subdomain */
#define DKIM_SIGERROR_MULTIREPLY    30  /* multiple records returned */
#define DKIM_SIGERROR_EMPTY_H       31  /* h= empty */
#define DKIM_SIGERROR_INVALID_H     32  /* h= missing req'd entries */
#define DKIM_SIGERROR_TOOLARGE_L    33  /* l= value exceeds body size */
#define DKIM_SIGERROR_MBSFAILED     34  /* "must be signed" failure */
#define DKIM_SIGERROR_KEYVERSION    35  /* unknown key version */
#define DKIM_SIGERROR_KEYUNKNOWNHASH    36  /* unknown key hash */
#define DKIM_SIGERROR_KEYHASHMISMATCH   37  /* sig-key hash mismatch */
#define DKIM_SIGERROR_NOTEMAILKEY   38  /* not an e-mail key */
#define DKIM_SIGERROR_UNUSED2       39  /* OBSOLETE */
#define DKIM_SIGERROR_KEYTYPEMISSING    40  /* key type missing */
#define DKIM_SIGERROR_KEYTYPEUNKNOWN    41  /* key type unknown */
#define DKIM_SIGERROR_KEYREVOKED    42  /* key revoked */
#define DKIM_SIGERROR_KEYDECODE     43  /* key couldn't be decoded */
#define DKIM_SIGERROR_MISSING_V     44  /* v= tag missing */
#define DKIM_SIGERROR_EMPTY_V       45  /* v= tag empty */

#ifdef  __cplusplus
extern "C" {
#endif

/* Check results */
enum rspamd_dkim_check_rcode {
	DKIM_CONTINUE = 0,
	DKIM_REJECT,
	DKIM_TRYAGAIN,
	DKIM_NOTFOUND,
	DKIM_RECORD_ERROR,
	DKIM_PERM_ERROR,
};

#define DKIM_CANON_SIMPLE   0   /* as specified in DKIM spec */
#define DKIM_CANON_RELAXED  1   /* as specified in DKIM spec */

struct rspamd_dkim_context_s;
typedef struct rspamd_dkim_context_s rspamd_dkim_context_t;

struct rspamd_dkim_sign_context_s;
typedef struct rspamd_dkim_sign_context_s rspamd_dkim_sign_context_t;

struct rspamd_dkim_key_s;
typedef struct rspamd_dkim_key_s rspamd_dkim_key_t;
typedef struct rspamd_dkim_key_s rspamd_dkim_sign_key_t;

struct rspamd_task;

enum rspamd_dkim_key_format {
	RSPAMD_DKIM_KEY_FILE = 0,
	RSPAMD_DKIM_KEY_PEM,
	RSPAMD_DKIM_KEY_BASE64,
	RSPAMD_DKIM_KEY_RAW,
	RSPAMD_DKIM_KEY_UNKNOWN
};

enum rspamd_dkim_type {
	RSPAMD_DKIM_NORMAL,
	RSPAMD_DKIM_ARC_SIG,
	RSPAMD_DKIM_ARC_SEAL
};

/* Signature methods */
enum rspamd_sign_type {
	DKIM_SIGN_UNKNOWN = -2,
	DKIM_SIGN_RSASHA1 = 0,
	DKIM_SIGN_RSASHA256,
	DKIM_SIGN_RSASHA512,
	DKIM_SIGN_ECDSASHA256,
	DKIM_SIGN_ECDSASHA512,
	DKIM_SIGN_EDDSASHA256,
};

enum rspamd_dkim_key_type {
	RSPAMD_DKIM_KEY_RSA = 0,
	RSPAMD_DKIM_KEY_ECDSA,
	RSPAMD_DKIM_KEY_EDDSA
};

struct rspamd_dkim_check_result {
	enum rspamd_dkim_check_rcode rcode;
	rspamd_dkim_context_t *ctx;
	/* Processed parts */
	const gchar *selector;
	const gchar *domain;
	const gchar *short_b;
	const gchar *fail_reason;
};


/* Err MUST be freed if it is not NULL, key is allocated by slice allocator */
typedef void (*dkim_key_handler_f) (rspamd_dkim_key_t *key, gsize keylen,
									rspamd_dkim_context_t *ctx, gpointer ud, GError *err);

/**
 * Create new dkim context from signature
 * @param sig message's signature
 * @param pool pool to allocate memory from
 * @param time_jitter jitter in seconds to allow time diff while checking
 * @param err pointer to error object
 * @return new context or NULL
 */
rspamd_dkim_context_t *rspamd_create_dkim_context (const gchar *sig,
												   rspamd_mempool_t *pool,
												   struct rspamd_dns_resolver *resolver,
												   guint time_jitter,
												   enum rspamd_dkim_type type,
												   GError **err);

/**
 * Create new dkim context for making a signature
 * @param task
 * @param priv_key
 * @param err
 * @return
 */
rspamd_dkim_sign_context_t *rspamd_create_dkim_sign_context (struct rspamd_task *task,
															 rspamd_dkim_sign_key_t *priv_key,
															 gint headers_canon,
															 gint body_canon,
															 const gchar *dkim_headers,
															 enum rspamd_dkim_type type,
															 GError **err);

/**
 * Load dkim key
 * @param path
 * @param err
 * @return
 */
rspamd_dkim_sign_key_t *rspamd_dkim_sign_key_load (const gchar *what, gsize len,
												   enum rspamd_dkim_key_format type,
												   GError **err);

/**
 * Invalidate modified sign key
 * @param key
 * @return
*/
gboolean rspamd_dkim_sign_key_maybe_invalidate (rspamd_dkim_sign_key_t *key,
												time_t mtime);

/**
 * Make DNS request for specified context and obtain and parse key
 * @param ctx dkim context from signature
 * @param resolver dns resolver object
 * @param s async session to make request
 * @return
 */
gboolean rspamd_get_dkim_key (rspamd_dkim_context_t *ctx,
							  struct rspamd_task *task,
							  dkim_key_handler_f handler,
							  gpointer ud);

/**
 * Check task for dkim context using dkim key
 * @param ctx dkim verify context
 * @param key dkim key (from cache or from dns request)
 * @param task task to check
 * @return
 */
struct rspamd_dkim_check_result *rspamd_dkim_check (rspamd_dkim_context_t *ctx,
													rspamd_dkim_key_t *key,
													struct rspamd_task *task);

struct rspamd_dkim_check_result *
rspamd_dkim_create_result (rspamd_dkim_context_t *ctx,
						   enum rspamd_dkim_check_rcode rcode,
						   struct rspamd_task *task);

GString *rspamd_dkim_sign (struct rspamd_task *task,
						   const gchar *selector,
						   const gchar *domain,
						   time_t expire,
						   gsize len,
						   guint idx,
						   const gchar *arc_cv,
						   rspamd_dkim_sign_context_t *ctx);

rspamd_dkim_key_t *rspamd_dkim_key_ref (rspamd_dkim_key_t *k);

void rspamd_dkim_key_unref (rspamd_dkim_key_t *k);

rspamd_dkim_sign_key_t *rspamd_dkim_sign_key_ref (rspamd_dkim_sign_key_t *k);

void rspamd_dkim_sign_key_unref (rspamd_dkim_sign_key_t *k);

const gchar *rspamd_dkim_get_domain (rspamd_dkim_context_t *ctx);

const gchar *rspamd_dkim_get_selector (rspamd_dkim_context_t *ctx);

const gchar *rspamd_dkim_get_dns_key (rspamd_dkim_context_t *ctx);

guint rspamd_dkim_key_get_ttl (rspamd_dkim_key_t *k);

/**
 * Create DKIM public key from a raw data
 * @param keydata
 * @param keylen
 * @param type
 * @param err
 * @return
 */
rspamd_dkim_key_t *rspamd_dkim_make_key (const gchar *keydata, guint keylen,
										 enum rspamd_dkim_key_type type,
										 GError **err);

#define RSPAMD_DKIM_KEY_ID_LEN 16
/**
 * Returns key id for dkim key (raw md5 of RSPAMD_DKIM_KEY_ID_LEN)
 * NOT ZERO TERMINATED, use RSPAMD_DKIM_KEY_ID_LEN for length
 * @param key
 * @return
 */
const guchar *rspamd_dkim_key_id (rspamd_dkim_key_t *key);

/**
 * Parse DKIM public key from a TXT record
 * @param txt
 * @param keylen
 * @param err
 * @return
 */
rspamd_dkim_key_t *rspamd_dkim_parse_key (const gchar *txt, gsize *keylen,
										  GError **err);

/**
 * Canonocalise header using relaxed algorithm
 * @param hname
 * @param hvalue
 * @param out
 * @param outlen
 * @return
 */
goffset rspamd_dkim_canonize_header_relaxed_str (const gchar *hname,
												 const gchar *hvalue,
												 gchar *out,
												 gsize outlen);

/**
 * Checks public and private keys for match
 * @param pk
 * @param sk
 * @param err
 * @return
 */
gboolean rspamd_dkim_match_keys (rspamd_dkim_key_t *pk,
								 rspamd_dkim_sign_key_t *sk,
								 GError **err);

/**
 * Free DKIM key
 * @param key
 */
void rspamd_dkim_key_free (rspamd_dkim_key_t *key);

#ifdef  __cplusplus
}
#endif

#endif /* DKIM_H_ */
