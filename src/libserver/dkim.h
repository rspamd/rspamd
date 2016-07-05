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
#include "event.h"
#include "dns.h"
#include "ref.h"

/* Main types and definitions */

#define DKIM_SIGNHEADER     "DKIM-Signature"
/* DKIM signature header */


/* Errors (from OpenDKIM) */

#define DKIM_SIGERROR_UNKNOWN       (-1)    /* unknown error */
#define DKIM_SIGERROR_OK        0   /* no error */
#define DKIM_SIGERROR_VERSION       1   /* unsupported version */
#define DKIM_SIGERROR_DOMAIN        2   /* invalid domain (d=/i=) */
#define DKIM_SIGERROR_EXPIRED       3   /* signature expired */
#define DKIM_SIGERROR_FUTURE        4   /* signature in the future */
#define DKIM_SIGERROR_TIMESTAMPS    5   /* x= < t= */
#define DKIM_SIGERROR_UNUSED        6   /* OBSOLETE */
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

/* Check results */
#define DKIM_CONTINUE   0   /* continue */
#define DKIM_REJECT 1   /* reject */
#define DKIM_TRYAGAIN   2   /* try again later */
#define DKIM_NOTFOUND   3   /* requested record not found */
#define DKIM_RECORD_ERROR   4   /* error requesting record */

#define DKIM_CANON_SIMPLE   0   /* as specified in DKIM spec */
#define DKIM_CANON_RELAXED  1   /* as specified in DKIM spec */

struct rspamd_dkim_context_s;
typedef struct rspamd_dkim_context_s rspamd_dkim_context_t;

struct rspamd_dkim_sign_context_s;
typedef struct rspamd_dkim_sign_context_s rspamd_dkim_sign_context_t;

struct rspamd_dkim_key_s;
typedef struct rspamd_dkim_key_s rspamd_dkim_key_t;

struct rspamd_dkim_sign_key_s;
typedef struct rspamd_dkim_sign_key_s rspamd_dkim_sign_key_t;

struct rspamd_task;

/* Err MUST be freed if it is not NULL, key is allocated by slice allocator */
typedef void (*dkim_key_handler_f)(rspamd_dkim_key_t *key, gsize keylen,
	rspamd_dkim_context_t *ctx, gpointer ud, GError *err);

/**
 * Create new dkim context from signature
 * @param sig message's signature
 * @param pool pool to allocate memory from
 * @param time_jitter jitter in seconds to allow time diff while checking
 * @param err pointer to error object
 * @return new context or NULL
 */
rspamd_dkim_context_t * rspamd_create_dkim_context (const gchar *sig,
	rspamd_mempool_t *pool,
	guint time_jitter,
	GError **err);

/**
 * Create new dkim context for making a signature
 * @param task
 * @param priv_key
 * @param err
 * @return
 */
rspamd_dkim_sign_context_t * rspamd_create_dkim_sign_context (struct rspamd_task *task,
		rspamd_dkim_sign_key_t *priv_key,
		gint headers_canon,
		gint body_canon,
		const gchar *dkim_headers,
		GError **err);

/**
 * Load dkim key from a file
 * @param path
 * @param err
 * @return
 */
rspamd_dkim_sign_key_t* rspamd_dkim_sign_key_load (const gchar *path, GError **err);

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
gint rspamd_dkim_check (rspamd_dkim_context_t *ctx,
	rspamd_dkim_key_t *key,
	struct rspamd_task *task);

GString* rspamd_dkim_sign (struct rspamd_task *task,
		const gchar *selector, const gchar *domain,
		time_t expire, gsize len,
		rspamd_dkim_sign_context_t *ctx);

rspamd_dkim_key_t * rspamd_dkim_key_ref (rspamd_dkim_key_t *k);
void rspamd_dkim_key_unref (rspamd_dkim_key_t *k);
rspamd_dkim_sign_key_t * rspamd_dkim_sign_key_ref (rspamd_dkim_sign_key_t *k);
void rspamd_dkim_sign_key_unref (rspamd_dkim_sign_key_t *k);
const gchar* rspamd_dkim_get_domain (rspamd_dkim_context_t *ctx);
const gchar* rspamd_dkim_get_dns_key (rspamd_dkim_context_t *ctx);
guint rspamd_dkim_key_get_ttl (rspamd_dkim_key_t *k);

/**
 * Free DKIM key
 * @param key
 */
void rspamd_dkim_key_free (rspamd_dkim_key_t *key);

#endif /* DKIM_H_ */
