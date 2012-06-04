/* Copyright (c) 2010-2011, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#ifndef DKIM_H_
#define DKIM_H_

#include "config.h"
#include "event.h"
#include "dns.h"
#ifdef HAVE_OPENSSL
#include <openssl/rsa.h>
#include <openssl/engine.h>
#endif

/* Main types and definitions */

#define	DKIM_SIGNHEADER		"DKIM-Signature"
					/* DKIM signature header */

/* special DNS tokens */
#define	DKIM_DNSKEYNAME		"_domainkey"
					/* reserved DNS sub-zone */
#define	DKIM_DNSPOLICYNAME	"_adsp"	/* reserved DNS sub-zone */

/* Canonization methods */
#define DKIM_CANON_UNKNOWN	(-1)	/* unknown method */
#define DKIM_CANON_SIMPLE	0	/* as specified in DKIM spec */
#define DKIM_CANON_RELAXED	1	/* as specified in DKIM spec */

#define DKIM_CANON_DEFAULT	DKIM_CANON_SIMPLE

/* Signature methods */
#define DKIM_SIGN_UNKNOWN	(-2)	/* unknown method */
#define DKIM_SIGN_DEFAULT	(-1)	/* use internal default */
#define DKIM_SIGN_RSASHA1	0	/* an RSA-signed SHA1 digest */
#define DKIM_SIGN_RSASHA256	1	/* an RSA-signed SHA256 digest */

/* Params */
#define DKIM_PARAM_UNKNOWN	(-1)	/* unknown */
#define DKIM_PARAM_SIGNATURE	0	/* b */
#define DKIM_PARAM_SIGNALG	1	/* a */
#define DKIM_PARAM_DOMAIN	2	/* d */
#define DKIM_PARAM_CANONALG	3	/* c */
#define DKIM_PARAM_QUERYMETHOD	4	/* q */
#define DKIM_PARAM_SELECTOR	5	/* s */
#define DKIM_PARAM_HDRLIST	6	/* h */
#define DKIM_PARAM_VERSION	7	/* v */
#define DKIM_PARAM_IDENTITY	8	/* i */
#define DKIM_PARAM_TIMESTAMP	9	/* t */
#define DKIM_PARAM_EXPIRATION	10	/* x */
#define DKIM_PARAM_COPIEDHDRS	11	/* z */
#define DKIM_PARAM_BODYHASH	12	/* bh */
#define DKIM_PARAM_BODYLENGTH	13	/* l */

/* Errors (from OpenDKIM) */

#define DKIM_SIGERROR_UNKNOWN		(-1)	/* unknown error */
#define DKIM_SIGERROR_OK		0	/* no error */
#define DKIM_SIGERROR_VERSION		1	/* unsupported version */
#define DKIM_SIGERROR_DOMAIN		2	/* invalid domain (d=/i=) */
#define DKIM_SIGERROR_EXPIRED		3	/* signature expired */
#define DKIM_SIGERROR_FUTURE		4	/* signature in the future */
#define DKIM_SIGERROR_TIMESTAMPS	5	/* x= < t= */
#define DKIM_SIGERROR_UNUSED		6	/* OBSOLETE */
#define DKIM_SIGERROR_INVALID_HC	7	/* c= invalid (header) */
#define DKIM_SIGERROR_INVALID_BC	8	/* c= invalid (body) */
#define DKIM_SIGERROR_MISSING_A		9	/* a= missing */
#define DKIM_SIGERROR_INVALID_A		10	/* a= invalid */
#define DKIM_SIGERROR_MISSING_H		11	/* h= missing */
#define DKIM_SIGERROR_INVALID_L		12	/* l= invalid */
#define DKIM_SIGERROR_INVALID_Q		13	/* q= invalid */
#define DKIM_SIGERROR_INVALID_QO	14	/* q= option invalid */
#define DKIM_SIGERROR_MISSING_D		15	/* d= missing */
#define DKIM_SIGERROR_EMPTY_D		16	/* d= empty */
#define DKIM_SIGERROR_MISSING_S		17	/* s= missing */
#define DKIM_SIGERROR_EMPTY_S		18	/* s= empty */
#define DKIM_SIGERROR_MISSING_B		19	/* b= missing */
#define DKIM_SIGERROR_EMPTY_B		20	/* b= empty */
#define DKIM_SIGERROR_CORRUPT_B		21	/* b= corrupt */
#define DKIM_SIGERROR_NOKEY		22	/* no key found in DNS */
#define DKIM_SIGERROR_DNSSYNTAX		23	/* DNS reply corrupt */
#define DKIM_SIGERROR_KEYFAIL		24	/* DNS query failed */
#define DKIM_SIGERROR_MISSING_BH	25	/* bh= missing */
#define DKIM_SIGERROR_EMPTY_BH		26	/* bh= empty */
#define DKIM_SIGERROR_CORRUPT_BH	27	/* bh= corrupt */
#define DKIM_SIGERROR_BADSIG		28	/* signature mismatch */
#define DKIM_SIGERROR_SUBDOMAIN		29	/* unauthorized subdomain */
#define DKIM_SIGERROR_MULTIREPLY	30	/* multiple records returned */
#define DKIM_SIGERROR_EMPTY_H		31	/* h= empty */
#define DKIM_SIGERROR_INVALID_H		32	/* h= missing req'd entries */
#define DKIM_SIGERROR_TOOLARGE_L	33	/* l= value exceeds body size */
#define DKIM_SIGERROR_MBSFAILED		34	/* "must be signed" failure */
#define	DKIM_SIGERROR_KEYVERSION	35	/* unknown key version */
#define	DKIM_SIGERROR_KEYUNKNOWNHASH	36	/* unknown key hash */
#define	DKIM_SIGERROR_KEYHASHMISMATCH	37	/* sig-key hash mismatch */
#define	DKIM_SIGERROR_NOTEMAILKEY	38	/* not an e-mail key */
#define	DKIM_SIGERROR_UNUSED2		39	/* OBSOLETE */
#define	DKIM_SIGERROR_KEYTYPEMISSING	40	/* key type missing */
#define	DKIM_SIGERROR_KEYTYPEUNKNOWN	41	/* key type unknown */
#define	DKIM_SIGERROR_KEYREVOKED	42	/* key revoked */
#define	DKIM_SIGERROR_KEYDECODE		43	/* key couldn't be decoded */
#define	DKIM_SIGERROR_MISSING_V		44	/* v= tag missing */
#define	DKIM_SIGERROR_EMPTY_V		45	/* v= tag empty */

/* Check results */
#define	DKIM_CONTINUE	0	/* continue */
#define	DKIM_REJECT	1	/* reject */
#define	DKIM_TRYAGAIN	2	/* try again later */
#define	DKIM_NOTFOUND	3	/* requested record not found */
#define	DKIM_RECORD_ERROR	4	/* error requesting record */

typedef struct rspamd_dkim_context_s {
	memory_pool_t *pool;
	gint sig_alg;
	gint header_canon_type;
	gint body_canon_type;
	gsize len;
	gchar *domain;
	gchar *selector;
	time_t timestamp;
	time_t expiration;
	gint8 *b;
	gint8 *bh;
	guint bhlen;
	guint blen;
	GPtrArray *hlist;
	guint ver;
	gchar *dns_key;
	GChecksum *headers_hash;
	GChecksum *body_hash;
} rspamd_dkim_context_t;

typedef struct rspamd_dkim_key_s {
	guint8 *keydata;
	guint keylen;
	gsize decoded_len;
#ifdef HAVE_OPENSSL
	RSA *key_rsa;
	BIO *key_bio;
	EVP_PKEY *key_evp;
#endif
}
rspamd_dkim_key_t;

struct worker_task;

/* Err MUST be freed if it is not NULL, key is allocated by slice allocator */
typedef void (*dkim_key_handler_f)(rspamd_dkim_key_t *key, gsize keylen, rspamd_dkim_context_t *ctx, gpointer ud, GError *err);

/**
 * Create new dkim context from signature
 * @param sig message's signature
 * @param pool pool to allocate memory from
 * @param err pointer to error object
 * @return new context or NULL
 */
rspamd_dkim_context_t* rspamd_create_dkim_context (const gchar *sig, memory_pool_t *pool, GError **err);

/**
 * Make DNS request for specified context and obtain and parse key
 * @param ctx dkim context from signature
 * @param resolver dns resolver object
 * @param s async session to make request
 * @return
 */
gboolean rspamd_get_dkim_key (rspamd_dkim_context_t *ctx, struct rspamd_dns_resolver *resolver,
		struct rspamd_async_session *s, dkim_key_handler_f handler, gpointer ud);

/**
 * Check task for dkim context using dkim key
 * @param ctx dkim verify context
 * @param key dkim key (from cache or from dns request)
 * @param task task to check
 * @return
 */
gint rspamd_dkim_check (rspamd_dkim_context_t *ctx, rspamd_dkim_key_t *key, struct worker_task *task);

/**
 * Free DKIM key
 * @param key
 */
void rspamd_dkim_key_free (rspamd_dkim_key_t *key);

#endif /* DKIM_H_ */
