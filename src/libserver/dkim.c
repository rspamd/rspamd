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
#include "config.h"
#include "rspamd.h"
#include "message.h"
#include "dkim.h"
#include "dns.h"
#include "utlist.h"
#include "unix-std.h"
#include "mempool_vars_internal.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

/* special DNS tokens */
#define DKIM_DNSKEYNAME     "_domainkey"

/* Canonization methods */
#define DKIM_CANON_UNKNOWN  (-1)    /* unknown method */
#define DKIM_CANON_SIMPLE   0   /* as specified in DKIM spec */
#define DKIM_CANON_RELAXED  1   /* as specified in DKIM spec */

#define DKIM_CANON_DEFAULT  DKIM_CANON_SIMPLE

#define RSPAMD_SHORT_BH_LEN 8

/* Params */
enum rspamd_dkim_param_type {
	DKIM_PARAM_UNKNOWN = -1,
	DKIM_PARAM_SIGNATURE = 0,
	DKIM_PARAM_SIGNALG,
	DKIM_PARAM_DOMAIN,
	DKIM_PARAM_CANONALG,
	DKIM_PARAM_QUERYMETHOD,
	DKIM_PARAM_SELECTOR,
	DKIM_PARAM_HDRLIST,
	DKIM_PARAM_VERSION,
	DKIM_PARAM_IDENTITY,
	DKIM_PARAM_TIMESTAMP,
	DKIM_PARAM_EXPIRATION,
	DKIM_PARAM_COPIEDHDRS,
	DKIM_PARAM_BODYHASH,
	DKIM_PARAM_BODYLENGTH,
	DKIM_PARAM_IDX,
	DKIM_PARAM_CV,
	DKIM_PARAM_IGNORE
};

#define RSPAMD_DKIM_MAX_ARC_IDX 10

#define msg_err_dkim(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        "dkim", ctx->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_dkim(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        "dkim", ctx->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_dkim(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "dkim", ctx->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_dkim(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_dkim_log_id, "dkim", ctx->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(dkim)

#define RSPAMD_DKIM_FLAG_OVERSIGN (1u << 0)

union rspamd_dkim_header_stat {
	struct _st {
		guint16 count;
		guint16 flags;
	} s;
	guint32 n;
};

struct rspamd_dkim_common_ctx {
	rspamd_mempool_t *pool;
	guint64 sig_hash;
	gsize len;
	gint header_canon_type;
	gint body_canon_type;
	GPtrArray *hlist;
	GHashTable *htable; /* header -> count mapping */
	EVP_MD_CTX *headers_hash;
	EVP_MD_CTX *body_hash;
	enum rspamd_dkim_type type;
	guint idx;
};

enum rspamd_arc_seal_cv {
	RSPAMD_ARC_UNKNOWN = 0,
	RSPAMD_ARC_NONE,
	RSPAMD_ARC_INVALID,
	RSPAMD_ARC_FAIL,
	RSPAMD_ARC_PASS
};


struct rspamd_dkim_context_s {
	struct rspamd_dkim_common_ctx common;
	rspamd_mempool_t *pool;
	gsize blen;
	gsize bhlen;
	gint sig_alg;
	guint ver;
	time_t timestamp;
	time_t expiration;
	gchar *domain;
	gchar *selector;
	gint8 *b;
	gchar *short_b;
	gint8 *bh;
	gchar *dns_key;
	enum rspamd_arc_seal_cv cv;
	const gchar *dkim_header;
};

struct rspamd_dkim_key_s {
	guint8 *keydata;
	guint keylen;
	gsize decoded_len;
	guint ttl;
	union {
		RSA *key_rsa;
		EC_KEY *key_ecdsa;
		guchar *key_eddsa;
	} key;
	enum rspamd_dkim_key_type type;
	BIO *key_bio;
	EVP_PKEY *key_evp;
	ref_entry_t ref;
};

struct rspamd_dkim_sign_context_s {
	struct rspamd_dkim_common_ctx common;
	rspamd_dkim_sign_key_t *key;
};

struct rspamd_dkim_sign_key_s {
	enum rspamd_dkim_sign_key_type type;
	guint8 *keydata;
	gsize keylen;
	RSA *key_rsa;
	BIO *key_bio;
	EVP_PKEY *key_evp;
	time_t mtime;
	ref_entry_t ref;
};


struct rspamd_dkim_header {
	const gchar *name;
	guint count;
};

/* Parser of dkim params */
typedef gboolean (*dkim_parse_param_f) (rspamd_dkim_context_t * ctx,
	const gchar *param, gsize len, GError **err);

static gboolean rspamd_dkim_parse_signature (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err);
static gboolean rspamd_dkim_parse_signalg (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err);
static gboolean rspamd_dkim_parse_domain (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err);
static gboolean rspamd_dkim_parse_canonalg (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err);
static gboolean rspamd_dkim_parse_ignore (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err);
static gboolean rspamd_dkim_parse_selector (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err);
static gboolean rspamd_dkim_parse_hdrlist (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err);
static gboolean rspamd_dkim_parse_version (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err);
static gboolean rspamd_dkim_parse_timestamp (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err);
static gboolean rspamd_dkim_parse_expiration (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err);
static gboolean rspamd_dkim_parse_bodyhash (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err);
static gboolean rspamd_dkim_parse_bodylength (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err);
static gboolean rspamd_dkim_parse_idx (rspamd_dkim_context_t * ctx,
		const gchar *param,
		gsize len,
		GError **err);
static gboolean rspamd_dkim_parse_cv (rspamd_dkim_context_t * ctx,
		const gchar *param,
		gsize len,
		GError **err);


static const dkim_parse_param_f parser_funcs[] = {
	[DKIM_PARAM_SIGNATURE] = rspamd_dkim_parse_signature,
	[DKIM_PARAM_SIGNALG] = rspamd_dkim_parse_signalg,
	[DKIM_PARAM_DOMAIN] = rspamd_dkim_parse_domain,
	[DKIM_PARAM_CANONALG] = rspamd_dkim_parse_canonalg,
	[DKIM_PARAM_QUERYMETHOD] = rspamd_dkim_parse_ignore,
	[DKIM_PARAM_SELECTOR] = rspamd_dkim_parse_selector,
	[DKIM_PARAM_HDRLIST] = rspamd_dkim_parse_hdrlist,
	[DKIM_PARAM_VERSION] = rspamd_dkim_parse_version,
	[DKIM_PARAM_IDENTITY] = rspamd_dkim_parse_ignore,
	[DKIM_PARAM_TIMESTAMP] = rspamd_dkim_parse_timestamp,
	[DKIM_PARAM_EXPIRATION] = rspamd_dkim_parse_expiration,
	[DKIM_PARAM_COPIEDHDRS] = rspamd_dkim_parse_ignore,
	[DKIM_PARAM_BODYHASH] = rspamd_dkim_parse_bodyhash,
	[DKIM_PARAM_BODYLENGTH] = rspamd_dkim_parse_bodylength,
	[DKIM_PARAM_IDX] = rspamd_dkim_parse_idx,
	[DKIM_PARAM_CV] = rspamd_dkim_parse_cv,
	[DKIM_PARAM_IGNORE] = rspamd_dkim_parse_ignore,
};

#define DKIM_ERROR dkim_error_quark ()
GQuark
dkim_error_quark (void)
{
	return g_quark_from_static_string ("dkim-error-quark");
}

/* Parsers implementation */
static gboolean
rspamd_dkim_parse_signature (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err)
{
	ctx->b = rspamd_mempool_alloc0 (ctx->pool, len);
	ctx->short_b = rspamd_mempool_alloc0 (ctx->pool, RSPAMD_SHORT_BH_LEN + 1);
	rspamd_strlcpy (ctx->short_b, param, MIN (len, RSPAMD_SHORT_BH_LEN + 1));
	(void)rspamd_cryptobox_base64_decode (param, len, ctx->b, &ctx->blen);

	return TRUE;
}

static gboolean
rspamd_dkim_parse_signalg (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err)
{
	/* XXX: ugly size comparison, improve this code style some day */
	if (len == 8) {
		if (memcmp (param, "rsa-sha1", len) == 0) {
			ctx->sig_alg = DKIM_SIGN_RSASHA1;
			return TRUE;
		}
	}
	else if (len == 10) {
		if (memcmp (param, "rsa-sha256", len) == 0) {
			ctx->sig_alg = DKIM_SIGN_RSASHA256;
			return TRUE;
		}
		else if (memcmp (param, "rsa-sha512", len) == 0) {
			ctx->sig_alg = DKIM_SIGN_RSASHA512;
			return TRUE;
		}
	}
	else if (len == 15) {
		if (memcmp (param, "ecdsa256-sha256", len) == 0) {
			ctx->sig_alg = DKIM_SIGN_ECDSASHA256;
			return TRUE;
		}
		else if (memcmp (param, "ecdsa256-sha512", len) == 0) {
			ctx->sig_alg = DKIM_SIGN_ECDSASHA512;
			return TRUE;
		}
	}
	else if (len == 14) {
		if (memcmp (param, "ed25519-sha256", len) == 0) {
			ctx->sig_alg = DKIM_SIGN_EDDSASHA256;
			return TRUE;
		}
	}

	g_set_error (err,
		DKIM_ERROR,
		DKIM_SIGERROR_INVALID_A,
		"invalid dkim sign algorithm");
	return FALSE;
}

static gboolean
rspamd_dkim_parse_domain (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err)
{
	ctx->domain = rspamd_mempool_alloc (ctx->pool, len + 1);
	rspamd_strlcpy (ctx->domain, param, len + 1);
	return TRUE;
}

static gboolean
rspamd_dkim_parse_canonalg (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err)
{
	const gchar *p, *slash = NULL, *end = param + len;
	gsize sl = 0;

	p = param;
	while (p != end) {
		if (*p == '/') {
			slash = p;
			break;
		}
		p++;
		sl++;
	}

	if (slash == NULL) {
		/* Only check header */
		if (len == 6 && memcmp (param, "simple", len) == 0) {
			ctx->common.header_canon_type = DKIM_CANON_SIMPLE;
			return TRUE;
		}
		else if (len == 7 && memcmp (param, "relaxed", len) == 0) {
			ctx->common.header_canon_type = DKIM_CANON_RELAXED;
			return TRUE;
		}
	}
	else {
		/* First check header */
		if (sl == 6 && memcmp (param, "simple", sl) == 0) {
			ctx->common.header_canon_type = DKIM_CANON_SIMPLE;
		}
		else if (sl == 7 && memcmp (param, "relaxed", sl) == 0) {
			ctx->common.header_canon_type = DKIM_CANON_RELAXED;
		}
		else {
			goto err;
		}
		/* Check body */
		len -= sl + 1;
		slash++;
		if (len == 6 && memcmp (slash, "simple", len) == 0) {
			ctx->common.body_canon_type = DKIM_CANON_SIMPLE;
			return TRUE;
		}
		else if (len == 7 && memcmp (slash, "relaxed", len) == 0) {
			ctx->common.body_canon_type = DKIM_CANON_RELAXED;
			return TRUE;
		}
	}

err:
	g_set_error (err,
		DKIM_ERROR,
		DKIM_SIGERROR_INVALID_A,
		"invalid dkim canonization algorithm");
	return FALSE;
}

static gboolean
rspamd_dkim_parse_ignore (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err)
{
	/* Just ignore unused params */
	return TRUE;
}

static gboolean
rspamd_dkim_parse_selector (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err)
{
	ctx->selector = rspamd_mempool_alloc (ctx->pool, len + 1);
	rspamd_strlcpy (ctx->selector, param, len + 1);
	return TRUE;
}

static void
rspamd_dkim_hlist_free (void *ud)
{
	GPtrArray *a = ud;

	g_ptr_array_free (a, TRUE);
}

static gboolean
rspamd_dkim_parse_hdrlist_common (struct rspamd_dkim_common_ctx *ctx,
	const gchar *param,
	gsize len,
	gboolean sign,
	GError **err)
{
	const gchar *c, *p, *end = param + len;
	gchar *h;
	gboolean from_found = FALSE, oversign;
	guint count = 0;
	struct rspamd_dkim_header *new;
	gpointer found;
	union rspamd_dkim_header_stat u;

	p = param;
	while (p <= end) {
		if ((p == end || *p == ':')) {
			count++;
		}
		p++;
	}

	if (count > 0) {
		ctx->hlist = g_ptr_array_sized_new (count);
	}
	else {
		return FALSE;
	}

	c = param;
	p = param;
	ctx->htable = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);

	while (p <= end) {
		if ((p == end || *p == ':') && p - c > 0) {
			oversign = FALSE;
			h = rspamd_mempool_alloc (ctx->pool, p - c + 1);
			rspamd_strlcpy (h, c, p - c + 1);

			g_strstrip (h);

			if (sign && rspamd_lc_cmp (h, "(o)", 3) == 0) {
				oversign = TRUE;
				h += 3;
				msg_debug_dkim ("oversign header: %s", h);
			}

			/* Check mandatory from */
			if (!from_found && g_ascii_strcasecmp (h, "from") == 0) {
				from_found = TRUE;
			}

			new = rspamd_mempool_alloc (ctx->pool,
					sizeof (struct rspamd_dkim_header));
			new->name = h;
			new->count = 0;
			u.n = 0;

			g_ptr_array_add (ctx->hlist, new);
			found = g_hash_table_lookup (ctx->htable, h);

			if (oversign) {
				if (found) {
					msg_err_dkim ("specified oversigned header more than once: %s",
							h);
				}

				u.s.flags |= RSPAMD_DKIM_FLAG_OVERSIGN;
				u.s.count = 0;
			}
			else {
				if (found != NULL) {
					u.n = GPOINTER_TO_UINT (found);
					new->count = u.s.count;
					u.s.count ++;
				}
				else {
					/* Insert new header order to the list */
					u.s.count = new->count + 1;
				}
			}

			g_hash_table_insert (ctx->htable, h, GUINT_TO_POINTER (u.n));

			c = p + 1;
			p++;
		}
		else {
			p++;
		}
	}

	if (!ctx->hlist) {
		g_set_error (err,
			DKIM_ERROR,
			DKIM_SIGERROR_INVALID_H,
			"invalid dkim header list");
		return FALSE;
	}
	else {
		if (!from_found) {
			g_ptr_array_free (ctx->hlist, TRUE);
			g_set_error (err,
				DKIM_ERROR,
				DKIM_SIGERROR_INVALID_H,
				"invalid dkim header list, from header is missing");
			return FALSE;
		}

		rspamd_mempool_add_destructor (ctx->pool,
			(rspamd_mempool_destruct_t)rspamd_dkim_hlist_free,
			ctx->hlist);
		rspamd_mempool_add_destructor (ctx->pool,
				(rspamd_mempool_destruct_t)g_hash_table_unref,
				ctx->htable);
	}

	return TRUE;
}

static gboolean
rspamd_dkim_parse_hdrlist (rspamd_dkim_context_t *ctx,
	const gchar *param,
	gsize len,
	GError **err)
{
	return rspamd_dkim_parse_hdrlist_common (&ctx->common, param, len, FALSE, err);
}

static gboolean
rspamd_dkim_parse_version (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err)
{
	if (len != 1 || *param != '1') {
		g_set_error (err,
			DKIM_ERROR,
			DKIM_SIGERROR_VERSION,
			"invalid dkim version");
		return FALSE;
	}

	ctx->ver = 1;
	return TRUE;
}

static gboolean
rspamd_dkim_parse_timestamp (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err)
{
	gulong val;

	if (!rspamd_strtoul (param, len, &val)) {
		g_set_error (err,
			DKIM_ERROR,
			DKIM_SIGERROR_UNKNOWN,
			"invalid dkim timestamp");
		return FALSE;
	}
	ctx->timestamp = val;

	return TRUE;
}

static gboolean
rspamd_dkim_parse_expiration (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err)
{
	gulong val;

	if (!rspamd_strtoul (param, len, &val)) {
		g_set_error (err,
			DKIM_ERROR,
			DKIM_SIGERROR_UNKNOWN,
			"invalid dkim expiration");
		return FALSE;
	}
	ctx->expiration = val;

	return TRUE;
}

static gboolean
rspamd_dkim_parse_bodyhash (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err)
{
	ctx->bh = rspamd_mempool_alloc0 (ctx->pool, len);
	(void)rspamd_cryptobox_base64_decode (param, len, ctx->bh, &ctx->bhlen);

	return TRUE;
}

static gboolean
rspamd_dkim_parse_bodylength (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err)
{
	gulong val;

	if (!rspamd_strtoul (param, len, &val)) {
		g_set_error (err,
			DKIM_ERROR,
			DKIM_SIGERROR_INVALID_L,
			"invalid dkim body length");
		return FALSE;
	}
	ctx->common.len = val;

	return TRUE;
}

static gboolean
rspamd_dkim_parse_idx (rspamd_dkim_context_t * ctx,
		const gchar *param,
		gsize len,
		GError **err)
{
	gulong val;

	if (!rspamd_strtoul (param, len, &val)) {
		g_set_error (err,
				DKIM_ERROR,
				DKIM_SIGERROR_INVALID_L,
				"invalid ARC idx");
		return FALSE;
	}
	ctx->common.idx = val;

	return TRUE;
}

static gboolean
rspamd_dkim_parse_cv (rspamd_dkim_context_t * ctx,
		const gchar *param,
		gsize len,
		GError **err)
{

	/* Only check header */
	if (len == 4 && memcmp (param, "fail", len) == 0) {
		ctx->cv = RSPAMD_ARC_FAIL;
		return TRUE;
	}
	else if (len == 4 && memcmp (param, "pass", len) == 0) {
		ctx->cv = RSPAMD_ARC_PASS;
		return TRUE;
	}
	else if (len == 4 && memcmp (param, "none", len) == 0) {
		ctx->cv = RSPAMD_ARC_NONE;
		return TRUE;
	}
	else if (len == 7 && memcmp (param, "invalid", len) == 0) {
		ctx->cv = RSPAMD_ARC_INVALID;
		return TRUE;
	}

	g_set_error (err,
			DKIM_ERROR,
			DKIM_SIGERROR_UNKNOWN,
			"invalid arc seal verification result");

	return FALSE;
}


static void
rspamd_dkim_add_arc_seal_headers (rspamd_mempool_t *pool,
		struct rspamd_dkim_common_ctx *ctx)
{
	struct rspamd_dkim_header *hdr;
	guint count = ctx->idx, i;

	ctx->hlist = g_ptr_array_sized_new (count * 3 - 1);

	for (i = 0; i < count; i ++) {
		/* Authentication results */
		hdr = rspamd_mempool_alloc (pool, sizeof (*hdr));
		hdr->name = RSPAMD_DKIM_ARC_AUTHHEADER;
		hdr->count = i;
		g_ptr_array_add (ctx->hlist, hdr);

		/* Arc signature */
		hdr = rspamd_mempool_alloc (pool, sizeof (*hdr));
		hdr->name = RSPAMD_DKIM_ARC_SIGNHEADER;
		hdr->count = i;
		g_ptr_array_add (ctx->hlist, hdr);

		/* Arc seal (except last one) */
		if (i != count - 1) {
			hdr = rspamd_mempool_alloc (pool, sizeof (*hdr));
			hdr->name = RSPAMD_DKIM_ARC_SEALHEADER;
			hdr->count = i;
			g_ptr_array_add (ctx->hlist, hdr);
		}
	}
}

/**
 * Create new dkim context from signature
 * @param sig message's signature
 * @param pool pool to allocate memory from
 * @param err pointer to error object
 * @return new context or NULL
 */
rspamd_dkim_context_t *
rspamd_create_dkim_context (const gchar *sig,
		rspamd_mempool_t *pool,
		guint time_jitter,
		enum rspamd_dkim_type type,
		GError **err)
{
	const gchar *p, *c, *tag = NULL, *end;
	gsize taglen;
	gint param = DKIM_PARAM_UNKNOWN;
	const EVP_MD *md_alg;
	time_t now;
	rspamd_dkim_context_t *ctx;
	enum {
		DKIM_STATE_TAG = 0,
		DKIM_STATE_AFTER_TAG,
		DKIM_STATE_VALUE,
		DKIM_STATE_SKIP_SPACES = 99,
		DKIM_STATE_ERROR = 100
	}                                state, next_state;


	if (sig == NULL) {
		g_set_error (err,
				DKIM_ERROR,
				DKIM_SIGERROR_EMPTY_B,
				"empty signature");
		return NULL;
	}

	ctx = rspamd_mempool_alloc0 (pool, sizeof (rspamd_dkim_context_t));
	ctx->pool = pool;

	if (type == RSPAMD_DKIM_ARC_SEAL) {
		ctx->common.header_canon_type = DKIM_CANON_RELAXED;
		ctx->common.body_canon_type = DKIM_CANON_RELAXED;
	}
	else {
		ctx->common.header_canon_type = DKIM_CANON_DEFAULT;
		ctx->common.body_canon_type = DKIM_CANON_DEFAULT;
	}

	ctx->sig_alg = DKIM_SIGN_UNKNOWN;
	ctx->common.pool = pool;
	ctx->common.type = type;
	/* A simple state machine of parsing tags */
	state = DKIM_STATE_SKIP_SPACES;
	next_state = DKIM_STATE_TAG;
	taglen = 0;
	p = sig;
	c = sig;
	end = p + strlen (p);
	ctx->common.sig_hash = rspamd_cryptobox_fast_hash (sig, end - sig,
			rspamd_hash_seed ());

	while (p <= end) {
		switch (state) {
		case DKIM_STATE_TAG:
			if (g_ascii_isspace (*p)) {
				taglen = p - c;
				while (*p && g_ascii_isspace (*p)) {
					/* Skip spaces before '=' sign */
					p++;
				}
				if (*p != '=') {
					g_set_error (err,
						DKIM_ERROR,
						DKIM_SIGERROR_UNKNOWN,
						"invalid dkim param");
					state = DKIM_STATE_ERROR;
				}
				else {
					state = DKIM_STATE_SKIP_SPACES;
					next_state = DKIM_STATE_AFTER_TAG;
					param = DKIM_PARAM_UNKNOWN;
					p++;
					tag = c;
				}
			}
			else if (*p == '=') {
				state = DKIM_STATE_SKIP_SPACES;
				next_state = DKIM_STATE_AFTER_TAG;
				param = DKIM_PARAM_UNKNOWN;
				p++;
				tag = c;
			}
			else {
				taglen++;
				p++;
			}
			break;
		case DKIM_STATE_AFTER_TAG:
			/* We got tag at tag and len at taglen */
			switch (taglen) {
			case 0:
				g_set_error (err,
					DKIM_ERROR,
					DKIM_SIGERROR_UNKNOWN,
					"zero length dkim param");
				state = DKIM_STATE_ERROR;
				break;
			case 1:
				/* Simple tags */
				switch (*tag) {
				case 'v':
					if (type == RSPAMD_DKIM_NORMAL) {
						param = DKIM_PARAM_VERSION;
					}
					else {
						g_set_error (err,
								DKIM_ERROR,
								DKIM_SIGERROR_UNKNOWN,
								"invalid ARC v param");
						state = DKIM_STATE_ERROR;
						break;
					}
					break;
				case 'a':
					param = DKIM_PARAM_SIGNALG;
					break;
				case 'b':
					param = DKIM_PARAM_SIGNATURE;
					break;
				case 'c':
					param = DKIM_PARAM_CANONALG;
					break;
				case 'd':
					param = DKIM_PARAM_DOMAIN;
					break;
				case 'h':
					if (type == RSPAMD_DKIM_ARC_SEAL) {
						g_set_error (err,
								DKIM_ERROR,
								DKIM_SIGERROR_UNKNOWN,
								"ARC seal must NOT have h= tag");
						state = DKIM_STATE_ERROR;
						break;
					}
					else {
						param = DKIM_PARAM_HDRLIST;
					}
					break;
				case 'i':
					if (type == RSPAMD_DKIM_NORMAL) {
						param = DKIM_PARAM_IDENTITY;
					}
					else {
						param = DKIM_PARAM_IDX;
					}
					break;
				case 'l':
					param = DKIM_PARAM_BODYLENGTH;
					break;
				case 'q':
					param = DKIM_PARAM_QUERYMETHOD;
					break;
				case 's':
					param = DKIM_PARAM_SELECTOR;
					break;
				case 't':
					param = DKIM_PARAM_TIMESTAMP;
					break;
				case 'x':
					param = DKIM_PARAM_EXPIRATION;
					break;
				case 'z':
					param = DKIM_PARAM_COPIEDHDRS;
					break;
				case 'r':
					param = DKIM_PARAM_IGNORE;
					break;
				default:
					g_set_error (err,
						DKIM_ERROR,
						DKIM_SIGERROR_UNKNOWN,
						"invalid dkim param: %c",
						*tag);
					state = DKIM_STATE_ERROR;
					break;
				}
				break;
			case 2:
				if (tag[0] == 'b' && tag[1] == 'h') {
					if (type == RSPAMD_DKIM_ARC_SEAL) {
						g_set_error (err,
								DKIM_ERROR,
								DKIM_SIGERROR_UNKNOWN,
								"ARC seal must NOT have bh= tag");
						state = DKIM_STATE_ERROR;
						break;
					}
					else {
						param = DKIM_PARAM_BODYHASH;
					}
				}
				else if (tag[0] == 'c' && tag[1] == 'v') {
					if (type != RSPAMD_DKIM_ARC_SEAL) {
						g_set_error (err,
								DKIM_ERROR,
								DKIM_SIGERROR_UNKNOWN,
								"cv tag is valid for ARC-Seal only");
						state = DKIM_STATE_ERROR;
						break;
					}
					else {
						param = DKIM_PARAM_CV;
					}
				}
				else {
					g_set_error (err,
						DKIM_ERROR,
						DKIM_SIGERROR_UNKNOWN,
						"invalid dkim param: %c%c",
						tag[0],
						tag[1]);
					state = DKIM_STATE_ERROR;
				}
				break;
			default:
				g_set_error (err,
					DKIM_ERROR,
					DKIM_SIGERROR_UNKNOWN,
					"invalid dkim param length: %zd",
					taglen);
				state = DKIM_STATE_ERROR;
				break;
			}
			if (state != DKIM_STATE_ERROR) {
				/* Skip spaces */
				state = DKIM_STATE_SKIP_SPACES;
				next_state = DKIM_STATE_VALUE;
			}
			break;
		case DKIM_STATE_VALUE:
			if (*p == ';') {
				if (param == DKIM_PARAM_UNKNOWN ||
					p - c == 0 ||
					!parser_funcs[param](ctx, c, p - c, err)) {
					state = DKIM_STATE_ERROR;
				}
				else {
					state = DKIM_STATE_SKIP_SPACES;
					next_state = DKIM_STATE_TAG;
					p++;
					taglen = 0;
				}
			}
			else if (p == end) {
				if (param == DKIM_PARAM_UNKNOWN ||
					!parser_funcs[param](ctx, c, p - c, err)) {
					state = DKIM_STATE_ERROR;
				}
				else {
					/* Finish processing */
					p++;
				}
			}
			else {
				p++;
			}
			break;
		case DKIM_STATE_SKIP_SPACES:
			if (g_ascii_isspace (*p)) {
				p++;
			}
			else {
				c = p;
				state = next_state;
			}
			break;
		case DKIM_STATE_ERROR:
			if (err && *err) {
				msg_info_dkim ("dkim parse failed: %s", (*err)->message);
				return NULL;
			}
			else {
				msg_info_dkim ("dkim parse failed: unknown error when parsing %c tag",
						*tag);
				return NULL;
			}
			break;
		}
	}

	if (type == RSPAMD_DKIM_ARC_SEAL) {
		rspamd_dkim_add_arc_seal_headers (pool, &ctx->common);
	}

	/* Now check validity of signature */
	if (ctx->b == NULL) {
		g_set_error (err,
			DKIM_ERROR,
			DKIM_SIGERROR_EMPTY_B,
			"b parameter missing");
		return NULL;
	}
	if (ctx->common.type != RSPAMD_DKIM_ARC_SEAL && ctx->bh == NULL) {
		g_set_error (err,
			DKIM_ERROR,
			DKIM_SIGERROR_EMPTY_BH,
			"bh parameter missing");
		return NULL;
	}
	if (ctx->domain == NULL) {
		g_set_error (err,
			DKIM_ERROR,
			DKIM_SIGERROR_EMPTY_D,
			"domain parameter missing");
		return NULL;
	}
	if (ctx->selector == NULL) {
		g_set_error (err,
			DKIM_ERROR,
			DKIM_SIGERROR_EMPTY_S,
			"selector parameter missing");
		return NULL;
	}
	if (ctx->common.type == RSPAMD_DKIM_NORMAL && ctx->ver == 0) {
		g_set_error (err,
			DKIM_ERROR,
			DKIM_SIGERROR_EMPTY_V,
			"v parameter missing");
		return NULL;
	}
	if (ctx->common.hlist == NULL) {
		g_set_error (err,
			DKIM_ERROR,
			DKIM_SIGERROR_EMPTY_H,
			"h parameter missing");
		return NULL;
	}
	if (ctx->sig_alg == DKIM_SIGN_UNKNOWN) {
		g_set_error (err,
			DKIM_ERROR,
			DKIM_SIGERROR_EMPTY_S,
			"s parameter missing");
		return NULL;
	}

	if (type != RSPAMD_DKIM_ARC_SEAL) {
		if (ctx->sig_alg == DKIM_SIGN_RSASHA1) {
			/* Check bh length */
			if (ctx->bhlen != (guint) EVP_MD_size (EVP_sha1 ())) {
				g_set_error (err,
						DKIM_ERROR,
						DKIM_SIGERROR_BADSIG,
						"signature has incorrect length: %zu",
						ctx->bhlen);
				return NULL;
			}

		} else if (ctx->sig_alg == DKIM_SIGN_RSASHA256 ||
				ctx->sig_alg == DKIM_SIGN_ECDSASHA256) {
			if (ctx->bhlen !=
					(guint) EVP_MD_size (EVP_sha256 ())) {
				g_set_error (err,
						DKIM_ERROR,
						DKIM_SIGERROR_BADSIG,
						"signature has incorrect length: %zu",
						ctx->bhlen);
				return NULL;
			}
		} else if (ctx->sig_alg == DKIM_SIGN_RSASHA512 ||
				ctx->sig_alg == DKIM_SIGN_ECDSASHA512) {
			if (ctx->bhlen !=
					(guint) EVP_MD_size (EVP_sha512 ())) {
				g_set_error (err,
						DKIM_ERROR,
						DKIM_SIGERROR_BADSIG,
						"signature has incorrect length: %zu",
						ctx->bhlen);
				return NULL;
			}
		}
	}

	/* Check expiration */
	now = time (NULL);
	if (ctx->timestamp && now < ctx->timestamp && ctx->timestamp - now >
		(gint)time_jitter) {
		g_set_error (err,
			DKIM_ERROR,
			DKIM_SIGERROR_FUTURE,
			"signature was made in future, ignoring");
		return NULL;
	}
	if (ctx->expiration && ctx->expiration < now) {
		g_set_error (err,
			DKIM_ERROR,
			DKIM_SIGERROR_EXPIRED,
			"signature has expired");
		return NULL;
	}

	if (ctx->common.type != RSPAMD_DKIM_NORMAL && (ctx->common.idx == 0 ||
			ctx->common.idx > RSPAMD_DKIM_MAX_ARC_IDX)) {
		g_set_error (err,
				DKIM_ERROR,
				DKIM_SIGERROR_UNKNOWN,
				"i parameter missing or invalid for ARC");
		return NULL;
	}

	if (ctx->common.type == RSPAMD_DKIM_ARC_SEAL) {
		if (ctx->cv == RSPAMD_ARC_UNKNOWN) {
			g_set_error (err,
					DKIM_ERROR,
					DKIM_SIGERROR_UNKNOWN,
					"cv parameter missing or invalid for ARC");
			return NULL;
		}
	}

	/* Now create dns key to request further */
	taglen = strlen (ctx->domain) + strlen (ctx->selector) +
		sizeof (DKIM_DNSKEYNAME) + 2;
	ctx->dns_key = rspamd_mempool_alloc (ctx->pool, taglen);
	rspamd_snprintf (ctx->dns_key,
		taglen,
		"%s.%s.%s",
		ctx->selector,
		DKIM_DNSKEYNAME,
		ctx->domain);

	/* Create checksums for further operations */
	if (ctx->sig_alg == DKIM_SIGN_RSASHA1) {
		md_alg = EVP_sha1 ();
	}
	else if (ctx->sig_alg == DKIM_SIGN_RSASHA256 ||
			ctx->sig_alg == DKIM_SIGN_ECDSASHA256 ||
			ctx->sig_alg == DKIM_SIGN_EDDSASHA256) {
		md_alg = EVP_sha256 ();
	}
	else if (ctx->sig_alg == DKIM_SIGN_RSASHA512 ||
			ctx->sig_alg == DKIM_SIGN_ECDSASHA512) {
		md_alg = EVP_sha512 ();
	}
	else {
		g_set_error (err,
			DKIM_ERROR,
			DKIM_SIGERROR_BADSIG,
			"signature has unsupported signature algorithm");

		return NULL;
	}
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	ctx->common.body_hash = EVP_MD_CTX_create ();
	EVP_DigestInit_ex (ctx->common.body_hash, md_alg, NULL);
	ctx->common.headers_hash = EVP_MD_CTX_create ();
	EVP_DigestInit_ex (ctx->common.headers_hash, md_alg, NULL);
	rspamd_mempool_add_destructor (pool,
			(rspamd_mempool_destruct_t)EVP_MD_CTX_destroy, ctx->common.body_hash);
	rspamd_mempool_add_destructor (pool,
			(rspamd_mempool_destruct_t)EVP_MD_CTX_destroy, ctx->common.headers_hash);
#else
	ctx->common.body_hash = EVP_MD_CTX_new ();
	EVP_DigestInit_ex (ctx->common.body_hash, md_alg, NULL);
	ctx->common.headers_hash = EVP_MD_CTX_new ();
	EVP_DigestInit_ex (ctx->common.headers_hash, md_alg, NULL);
	rspamd_mempool_add_destructor (pool,
			(rspamd_mempool_destruct_t)EVP_MD_CTX_free, ctx->common.body_hash);
	rspamd_mempool_add_destructor (pool,
			(rspamd_mempool_destruct_t)EVP_MD_CTX_free, ctx->common.headers_hash);
#endif
	ctx->dkim_header = sig;

	return ctx;
}

struct rspamd_dkim_key_cbdata {
	rspamd_dkim_context_t *ctx;
	dkim_key_handler_f handler;
	gpointer ud;
};

rspamd_dkim_key_t *
rspamd_dkim_make_key (const gchar *keydata,
		guint keylen, enum rspamd_dkim_key_type type, GError **err)
{
	rspamd_dkim_key_t *key = NULL;

	if (keylen < 3) {
		g_set_error (err,
				DKIM_ERROR,
				DKIM_SIGERROR_KEYFAIL,
				"DKIM key is too short to be valid");
		return NULL;
	}

	key = g_malloc0 (sizeof (rspamd_dkim_key_t));
	REF_INIT_RETAIN (key, rspamd_dkim_key_free);
	key->keydata = g_malloc0 (keylen + 1);
	key->decoded_len = keylen;
	key->keylen = keylen;
	key->type = type;

	rspamd_cryptobox_base64_decode (keydata, keylen, key->keydata,
			&key->decoded_len);

	if (key->type == RSPAMD_DKIM_KEY_EDDSA) {
		key->key.key_eddsa = key->keydata;

		if (key->decoded_len != rspamd_cryptobox_pk_sig_bytes (
				RSPAMD_CRYPTOBOX_MODE_25519)) {
			g_set_error (err,
					DKIM_ERROR,
					DKIM_SIGERROR_KEYFAIL,
					"DKIM key is has invalid length %d for eddsa",
					(gint)key->decoded_len);
			REF_RELEASE (key);

			return NULL;
		}
	}
	else {
		key->key_bio = BIO_new_mem_buf (key->keydata, key->decoded_len);

		if (key->key_bio == NULL) {
			g_set_error (err,
					DKIM_ERROR,
					DKIM_SIGERROR_KEYFAIL,
					"cannot make ssl bio from key");
			REF_RELEASE (key);

			return NULL;
		}

		key->key_evp = d2i_PUBKEY_bio (key->key_bio, NULL);

		if (key->key_evp == NULL) {
			g_set_error (err,
					DKIM_ERROR,
					DKIM_SIGERROR_KEYFAIL,
					"cannot extract pubkey from bio");
			REF_RELEASE (key);

			return NULL;
		}

		if (type == RSPAMD_DKIM_KEY_RSA) {
			key->key.key_rsa = EVP_PKEY_get1_RSA (key->key_evp);

			if (key->key.key_rsa == NULL) {
				g_set_error (err,
						DKIM_ERROR,
						DKIM_SIGERROR_KEYFAIL,
						"cannot extract rsa key from evp key");
				REF_RELEASE (key);

				return NULL;
			}
		} else {
			key->key.key_ecdsa = EVP_PKEY_get1_EC_KEY (key->key_evp);

			if (key->key.key_ecdsa == NULL) {
				g_set_error (err,
						DKIM_ERROR,
						DKIM_SIGERROR_KEYFAIL,
						"cannot extract ecdsa key from evp key");
				REF_RELEASE (key);

				return NULL;
			}
		}
	}

	return key;
}

/**
 * Free DKIM key
 * @param key
 */
void
rspamd_dkim_key_free (rspamd_dkim_key_t *key)
{
	if (key->key_evp) {
		EVP_PKEY_free (key->key_evp);
	}

	if (key->type == RSPAMD_DKIM_KEY_RSA) {
		if (key->key.key_rsa) {
			RSA_free (key->key.key_rsa);
		}
	}
	else if (key->type == RSPAMD_DKIM_KEY_ECDSA) {
		if (key->key.key_ecdsa) {
			EC_KEY_free (key->key.key_ecdsa);
		}
	}
	/* Nothing in case of eddsa key */
	if (key->key_bio) {
		BIO_free (key->key_bio);
	}

	g_free (key->keydata);
	g_free (key);
}

void
rspamd_dkim_sign_key_free (rspamd_dkim_sign_key_t *key)
{
	if (key->key_evp) {
		EVP_PKEY_free (key->key_evp);
	}
	if (key->key_rsa) {
		RSA_free (key->key_rsa);
	}
	if (key->key_bio) {
		BIO_free (key->key_bio);
	}

	if (key->keydata && key->keylen > 0) {

		if (key->type == RSPAMD_DKIM_SIGN_KEY_FILE) {
			munmap (key->keydata, key->keylen);
		}
		else {
			g_free (key->keydata);
		}
	}

	g_free (key);
}

rspamd_dkim_key_t *
rspamd_dkim_parse_key (const gchar *txt, gsize *keylen, GError **err)
{
	const gchar *c, *p, *end, *key = NULL, *alg = "rsa";
	enum {
		read_tag = 0,
		read_eqsign,
		read_p_tag,
		read_k_tag,
	} state = read_tag;
	gchar tag = '\0';
	gsize klen = 0, alglen = 0;

	c = txt;
	p = txt;
	end = txt + strlen (txt);

	while (p < end) {
		switch (state) {
		case read_tag:
			if (*p == '=') {
				state = read_eqsign;
			} else {
				tag = *p;
			}
			p++;
			break;
		case read_eqsign:
			if (tag == 'p') {
				state = read_p_tag;
				c = p;
			} else if (tag == 'k') {
				state = read_k_tag;
				c = p;
			} else {
				/* Unknown tag, ignore */
				state = read_tag;
				tag = '\0';
				p++;
			}
			break;
		case read_p_tag:
			if (*p == ';') {
				klen = p - c;
				key = c;
				state = read_tag;
				tag = '\0';
			}
			p++;
			break;
		case read_k_tag:
			if (*p == ';') {
				alglen = p - c;
				alg = c;
				state = read_tag;
				tag = '\0';
			}
			p++;
			break;
		default:
			break;
		}
	}

	/* Leftover */
	switch (state) {
	case read_p_tag:
		klen = p - c;
		key = c;
		break;
	case read_k_tag:
		alglen = p - c;
		alg = c;
		break;
	default:
		break;
	}

	if (klen == 0 || key == NULL) {
		g_set_error (err,
				DKIM_ERROR,
				DKIM_SIGERROR_KEYFAIL,
				"key is missing");

		return NULL;
	}

	if (alglen == 0 || alg == NULL) {
		alg = "rsa"; /* Implicit */
		alglen = 3;
	}

	if (keylen) {
		*keylen = klen;
	}

	if (alglen == 8 && rspamd_lc_cmp (alg, "ecdsa256", alglen) == 0) {
		return rspamd_dkim_make_key (c, klen,
				RSPAMD_DKIM_KEY_ECDSA, err);
	}
	else if (alglen == 7 && rspamd_lc_cmp (alg, "ed25519", alglen) == 0) {
		return rspamd_dkim_make_key (c, klen,
				RSPAMD_DKIM_KEY_EDDSA, err);
	}
	else {
		/* We assume RSA default in all cases */
		return rspamd_dkim_make_key (c, klen,
				RSPAMD_DKIM_KEY_RSA, err);
	}

	g_assert_not_reached ();

	return NULL;
}

/* Get TXT request data and parse it */
static void
rspamd_dkim_dns_cb (struct rdns_reply *reply, gpointer arg)
{
	struct rspamd_dkim_key_cbdata *cbdata = arg;
	rspamd_dkim_key_t *key = NULL;
	GError *err = NULL;
	struct rdns_reply_entry *elt;
	gsize keylen = 0;

	if (reply->code != RDNS_RC_NOERROR) {
		gint err_code = DKIM_SIGERROR_NOKEY;
		if (reply->code == RDNS_RC_NOREC) {
			err_code = DKIM_SIGERROR_NOREC;
		}
		else if (reply->code == RDNS_RC_NXDOMAIN) {
			err_code = DKIM_SIGERROR_NOREC;
		}
		g_set_error (&err,
			DKIM_ERROR,
			err_code,
			"dns request to %s failed: %s",
			cbdata->ctx->dns_key,
			rdns_strerror (reply->code));
		cbdata->handler (NULL, 0, cbdata->ctx, cbdata->ud, err);
	}
	else {
		LL_FOREACH (reply->entries, elt)
		{
			if (elt->type == RDNS_REQUEST_TXT) {
				if (err != NULL) {
					/* Free error as it is insignificant */
					g_error_free (err);
					err = NULL;
				}
				key = rspamd_dkim_parse_key (elt->content.txt.data,
						&keylen,
						&err);
				if (key) {
					key->ttl = elt->ttl;
					break;
				}
			}
		}
		cbdata->handler (key, keylen, cbdata->ctx, cbdata->ud, err);
	}
}

/**
 * Make DNS request for specified context and obtain and parse key
 * @param ctx dkim context from signature
 * @param resolver dns resolver object
 * @param s async session to make request
 * @return
 */
gboolean
rspamd_get_dkim_key (rspamd_dkim_context_t *ctx,
	struct rspamd_task *task,
	dkim_key_handler_f handler,
	gpointer ud)
{
	struct rspamd_dkim_key_cbdata *cbdata;

	g_return_val_if_fail (ctx != NULL,			FALSE);
	g_return_val_if_fail (ctx->dns_key != NULL, FALSE);

	cbdata =
		rspamd_mempool_alloc (ctx->pool,
			sizeof (struct rspamd_dkim_key_cbdata));
	cbdata->ctx = ctx;
	cbdata->handler = handler;
	cbdata->ud = ud;

	return make_dns_request_task_forced (task,
			   rspamd_dkim_dns_cb,
			   cbdata,
			   RDNS_REQUEST_TXT,
			   ctx->dns_key);
}

static gboolean
rspamd_dkim_relaxed_body_step (struct rspamd_dkim_common_ctx *ctx, EVP_MD_CTX *ck,
		const gchar **start, guint size,
		guint *remain)
{
	const gchar *h;
	static gchar buf[BUFSIZ];
	gchar *t;
	guint len, inlen, added = 0;
	gboolean got_sp;

	len = size;
	inlen = sizeof (buf) - 1;
	h = *start;
	t = buf;
	got_sp = FALSE;

	while (len && inlen) {
		if (*h == '\r' || *h == '\n') {
			if (got_sp) {
				/* Ignore spaces at the end of line */
				t --;
			}
			*t++ = '\r';
			*t++ = '\n';
			if (len > 1 && (*h == '\r' && h[1] == '\n')) {
				h += 2;
				len -= 2;
			}
			else {
				h ++;
				len --;
				added ++;
			}
			break;
		}
		else if (g_ascii_isspace (*h)) {
			if (got_sp) {
				/* Ignore multiply spaces */
				h++;
				len--;
				continue;
			}
			else {
				*t++ = ' ';
				h++;
				inlen--;
				len--;
				got_sp = TRUE;
				continue;
			}
		}
		else {
			got_sp = FALSE;
		}
		*t++ = *h++;
		inlen--;
		len--;
	}

	*start = h;

	if (*remain > 0) {
		size_t cklen = MIN(t - buf, *remain + added);
		EVP_DigestUpdate (ck, buf, cklen);
		*remain = *remain - (cklen - added);
#if 0
		msg_debug_dkim ("update signature with buffer (%ud size, %ud remain, %ud added): %*s",
				cklen, *remain, added, cklen, buf);
#else
		msg_debug_dkim ("update signature with body buffer "
				"(%ud size, %ud remain, %ud added)",
						cklen, *remain, added);
#endif
	}

	return (len != 0);
}

static gboolean
rspamd_dkim_simple_body_step (struct rspamd_dkim_common_ctx *ctx,
		EVP_MD_CTX *ck, const gchar **start, guint size,
		guint *remain)
{
	const gchar *h;
	static gchar buf[BUFSIZ];
	gchar *t;
	guint len, inlen, added = 0;

	len = size;
	inlen = sizeof (buf) - 1;
	h = *start;
	t = &buf[0];

	while (len && inlen) {
		if (*h == '\r' || *h == '\n') {
			*t++ = '\r';
			*t++ = '\n';
			if (len > 1 && (*h == '\r' && h[1] == '\n')) {
				h += 2;
				len -= 2;
			}
			else {
				h ++;
				len --;
				added ++;
			}
			break;
		}
		*t++ = *h++;
		inlen--;
		len--;
	}

	*start = h;

	if (*remain > 0) {
		size_t cklen = MIN(t - buf, *remain + added);
		EVP_DigestUpdate (ck, buf, cklen);
		*remain = *remain - (cklen - added);
		msg_debug_dkim ("update signature with body buffer "
				"(%ud size, %ud remain, %ud added)",
				cklen, *remain, added);
	}

	return (len != 0);
}

static const gchar *
rspamd_dkim_skip_empty_lines (const gchar *start, const gchar *end,
		guint type, gboolean sign, gboolean *need_crlf)
{
	const gchar *p = end - 1, *t;
	enum {
		init = 0,
		init_2,
		got_cr,
		got_lf,
		got_crlf,
		test_spaces,
	} state = init;
	guint skip = 0;

	while (p >= start) {
		switch (state) {
		case init:
			if (*p == '\r') {
				state = got_cr;
			}
			else if (*p == '\n') {
				state = got_lf;
			}
			else if (type == DKIM_CANON_RELAXED && *p == ' ') {
				skip = 0;
				state = test_spaces;
			}
			else {
				if (sign || type != DKIM_CANON_RELAXED) {
					*need_crlf = TRUE;
				}

				goto end;
			}
			break;
		case init_2:
			if (*p == '\r') {
				state = got_cr;
			}
			else if (*p == '\n') {
				state = got_lf;
			}
			else if (type == DKIM_CANON_RELAXED && (*p == ' ' || *p == '\t')) {
				skip = 0;
				state = test_spaces;
			}
			else {
				goto end;
			}
			break;
		case got_cr:
			if (p >= start + 1) {
				if (*(p - 1) == '\r') {
					p --;
					state = got_cr;
				}
				else if (*(p - 1) == '\n') {
					if ((*p - 2) == '\r') {
						/* \r\n\r -> we know about one line */
						p -= 1;
						state = got_crlf;
					}
					else {
						/* \n\r -> we know about one line */
						p -= 1;
						state = got_lf;
					}
				}
				else if (type == DKIM_CANON_RELAXED && (*(p - 1) == ' ' ||
						*(p - 1) == '\t')) {
					skip = 1;
					state = test_spaces;
				}
				else {
					goto end;
				}
			}
			else {
				if (g_ascii_isspace (*(p - 1))) {
					if (type == DKIM_CANON_RELAXED) {
						p -= 1;
					}
				}
				goto end;
			}
			break;
		case got_lf:
			if (p >= start + 1) {
				if (*(p - 1) == '\r') {
					state = got_crlf;
				}
				else if (*(p - 1) == '\n') {
					/* We know about one line */
					p --;
					state = got_lf;
				}
				else if (type == DKIM_CANON_RELAXED && (*(p - 1) == ' ' ||
						*(p - 1) == '\t')) {
					skip = 1;
					state = test_spaces;
				}
				else {
					goto end;
				}
			}
			else {
				if (g_ascii_isspace (*(p - 1))) {
					if (type == DKIM_CANON_RELAXED) {
						p -= 1;
					}
				}
				goto end;
			}
			break;
		case got_crlf:
			if (p >= start + 2) {
				if (*(p - 2) == '\r') {
					p -= 2;
					state = got_cr;
				}
				else if (*(p - 2) == '\n') {
					p -= 2;
					state = got_lf;
				}
				else if (type == DKIM_CANON_RELAXED && (*(p - 2) == ' ' ||
						*(p - 2) == '\t')) {
					skip = 2;
					state = test_spaces;
				}
				else {
					goto end;
				}
			}
			else {
				if (g_ascii_isspace (*(p - 2))) {
					if (type == DKIM_CANON_RELAXED) {
						p -= 2;
					}
				}
				goto end;
			}
			break;
		case test_spaces:
			t = p - skip;

			while (t >= start + 2 && (*t == ' ' || *t == '\t')) {
				t --;
			}

			if (*t == '\r') {
				p = t;
				state = got_cr;
			}
			else if (*t == '\n') {
				p = t;
				state = got_lf;
			}
			else {
				goto end;
			}
			break;
		}
	}

end:
	return p;
}

static gboolean
rspamd_dkim_canonize_body (struct rspamd_dkim_common_ctx *ctx,
	const gchar *start,
	const gchar *end,
	gboolean sign)
{
	const gchar *p;
	guint remain = ctx->len ? ctx->len : (guint)(end - start);
	gboolean need_crlf = FALSE;

	if (start == NULL) {
		/* Empty body */
		if (ctx->body_canon_type == DKIM_CANON_SIMPLE) {
			EVP_DigestUpdate (ctx->body_hash, CRLF, sizeof (CRLF) - 1);
		}
		else {
			EVP_DigestUpdate (ctx->body_hash, "", 0);
		}
	}
	else {
		/* Strip extra ending CRLF */
		p = rspamd_dkim_skip_empty_lines (start, end, ctx->body_canon_type,
				sign, &need_crlf);
		end = p + 1;

		if (end == start) {
			/* Empty body */
			if (ctx->body_canon_type == DKIM_CANON_SIMPLE) {
				EVP_DigestUpdate (ctx->body_hash, CRLF, sizeof (CRLF) - 1);
			}
			else {
				EVP_DigestUpdate (ctx->body_hash, "", 0);
			}
		}
		else {
			if (ctx->body_canon_type == DKIM_CANON_SIMPLE) {
				/* Simple canonization */
				while (rspamd_dkim_simple_body_step (ctx, ctx->body_hash,
						&start, end - start, &remain));

				if (need_crlf) {
					start = "\r\n";
					end = start + 2;
					remain = 2;
					rspamd_dkim_simple_body_step (ctx, ctx->body_hash,
							&start, end - start, &remain);
				}
			}
			else {
				while (rspamd_dkim_relaxed_body_step (ctx, ctx->body_hash,
						&start, end - start, &remain)) ;
				if (need_crlf) {
					start = "\r\n";
					end = start + 2;
					remain = 2;
					rspamd_dkim_relaxed_body_step (ctx, ctx->body_hash,
							&start, end - start, &remain);
				}
			}
		}
		return TRUE;
	}

	/* TODO: Implement relaxed algorithm */
	return FALSE;
}

/* Update hash converting all CR and LF to CRLF */
static void
rspamd_dkim_hash_update (EVP_MD_CTX *ck, const gchar *begin, gsize len)
{
	const gchar *p, *c, *end;

	end = begin + len;
	p = begin;
	c = p;

	while (p < end) {
		if (*p == '\r') {
			EVP_DigestUpdate (ck, c, p - c);
			EVP_DigestUpdate (ck, CRLF, sizeof (CRLF) - 1);
			p++;

			if (p < end && *p == '\n') {
				p++;
			}
			c = p;
		}
		else if (*p == '\n') {
			EVP_DigestUpdate (ck, c, p - c);
			EVP_DigestUpdate (ck, CRLF, sizeof (CRLF) - 1);
			p++;
			c = p;
		}
		else {
			p++;
		}
	}

	if (p > c) {
		EVP_DigestUpdate (ck, c, p - c);
	}
}

/* Update hash by signature value (ignoring b= tag) */
static void
rspamd_dkim_signature_update (struct rspamd_dkim_common_ctx *ctx,
	const gchar *begin,
	guint len)
{
	const gchar *p, *c, *end;
	gboolean tag, skip;

	end = begin + len;
	p = begin;
	c = begin;
	tag = TRUE;
	skip = FALSE;

	while (p < end) {
		if (tag && p[0] == 'b' && p[1] == '=') {
			/* Add to signature */
			msg_debug_dkim ("initial update hash with signature part: %*s",
				p - c + 2,
				c);
			rspamd_dkim_hash_update (ctx->headers_hash, c, p - c + 2);
			skip = TRUE;
		}
		else if (skip && (*p == ';' || p == end - 1)) {
			skip = FALSE;
			c = p;
		}
		else if (!tag && *p == ';') {
			tag = TRUE;
		}
		else if (tag && *p == '=') {
			tag = FALSE;
		}
		p++;
	}

	p--;
	/* Skip \r\n at the end */
	while ((*p == '\r' || *p == '\n') && p >= c) {
		p--;
	}

	if (p - c + 1 > 0) {
		msg_debug_dkim ("final update hash with signature part: %*s", p - c + 1, c);
		rspamd_dkim_hash_update (ctx->headers_hash, c, p - c + 1);
	}
}

goffset
rspamd_dkim_canonize_header_relaxed_str (const gchar *hname,
		const gchar *hvalue,
		gchar *out,
		gsize outlen)
{
	gchar *t;
	const guchar *h;
	gboolean got_sp;

	/* Name part */
	t = out;
	h = hname;

	while (*h && t - out < outlen) {
		*t++ = lc_map[*h++];
	}

	if (t - out >= outlen) {
		return -1;
	}

	*t++ = ':';

	/* Value part */
	h = hvalue;
	/* Skip spaces at the beginning */
	while (g_ascii_isspace (*h)) {
		h++;
	}

	got_sp = FALSE;

	while (*h && (t - out < outlen))  {
		if (g_ascii_isspace (*h)) {
			if (got_sp) {
				h++;
				continue;
			}
			else {
				got_sp = TRUE;
				*t++ = ' ';
				h++;
				continue;
			}
		}
		else {
			got_sp = FALSE;
		}

		*t++ = *h++;
	}

	if (g_ascii_isspace (*(t - 1))) {
		t--;
	}

	if (t - out >= outlen - 2) {
		return -1;
	}

	*t++ = '\r';
	*t++ = '\n';
	*t = '\0';

	return t - out;
}

static gboolean
rspamd_dkim_canonize_header_relaxed (struct rspamd_dkim_common_ctx *ctx,
	const gchar *header,
	const gchar *header_name,
	gboolean is_sign)
{
	static gchar st_buf[8192];
	gchar *buf;
	guint inlen;
	goffset r;
	gboolean allocated = FALSE;

	inlen = strlen (header) + strlen (header_name) + sizeof (":" CRLF);

	if (inlen > sizeof (st_buf)) {
		buf = g_malloc (inlen);
		allocated = TRUE;
	}
	else {
		/* Faster */
		buf = st_buf;
	}

	r = rspamd_dkim_canonize_header_relaxed_str (header_name, header, buf, inlen);

	g_assert (r != -1);

	if (!is_sign) {
		msg_debug_dkim ("update signature with header: %s", buf);
		EVP_DigestUpdate (ctx->headers_hash, buf, r);
	}
	else {
		rspamd_dkim_signature_update (ctx, buf, r);
	}

	if (allocated) {
		g_free (buf);
	}

	return TRUE;
}


static gboolean
rspamd_dkim_canonize_header (struct rspamd_dkim_common_ctx *ctx,
	struct rspamd_task *task,
	const gchar *header_name,
	guint count,
	const gchar *dkim_header,
	const gchar *dkim_domain)
{
	struct rspamd_mime_header *rh;
	gint rh_num = 0;
	GPtrArray *ar;

	if (dkim_header == NULL) {
		ar = g_hash_table_lookup (task->raw_headers, header_name);

		if (ar) {
			/* Check uniqueness of the header */
			rh = g_ptr_array_index (ar, 0);
			if ((rh->type & RSPAMD_HEADER_UNIQUE) && ar->len > 1) {
				guint64 random_cookie = ottery_rand_uint64 ();

				msg_warn_dkim ("header %s is intended to be unique by"
						" email standards, but we have %d headers of this"
						" type, artificially break DKIM check", header_name,
						ar->len);
				rspamd_dkim_hash_update (ctx->headers_hash,
						(const gchar *)&random_cookie,
						sizeof (random_cookie));

				return FALSE;
			}

			if (ar->len > count) {
				/* Set skip count */
				rh_num = ar->len - count - 1;
			}
			else {
				/*
				 * If DKIM has less headers requested than there are in a
				 * message, then it's fine, it allows adding extra headers
				 */
				return TRUE;
			}

			rh = g_ptr_array_index (ar, rh_num);

			if (ctx->header_canon_type == DKIM_CANON_SIMPLE) {
				rspamd_dkim_hash_update (ctx->headers_hash, rh->raw_value,
						rh->raw_len);
				msg_debug_dkim ("update signature with header: %*s",
						(gint)rh->raw_len, rh->raw_value);
			}
			else {
				if (!rspamd_dkim_canonize_header_relaxed (ctx, rh->value,
						header_name, FALSE)) {
					return FALSE;
				}
			}
		}
	}
	else {
		/* For signature check just use the saved dkim header */
		if (ctx->header_canon_type == DKIM_CANON_SIMPLE) {
			/* We need to find our own signature and use it */
			guint i;

			ar = g_hash_table_lookup (task->raw_headers, header_name);

			if (ar) {
				/* We need to find our own signature */
				if (!dkim_domain) {
					return FALSE;
				}

				PTR_ARRAY_FOREACH (ar, i, rh) {
					guint64 th = rspamd_cryptobox_fast_hash (rh->decoded,
							strlen (rh->decoded), rspamd_hash_seed ());

					if (th == ctx->sig_hash) {
						rspamd_dkim_signature_update (ctx, rh->raw_value,
								rh->raw_len);
						break;
					}
				}
			}
			else {
				return FALSE;
			}
		}
		else {
			if (!rspamd_dkim_canonize_header_relaxed (ctx,
					dkim_header,
					header_name,
					TRUE)) {
				return FALSE;
			}
		}
	}

	return TRUE;
}

struct rspamd_dkim_cached_hash {
	guchar *digest_normal;
	guchar *digest_cr;
	guchar *digest_crlf;
	gchar *type;
};

static struct rspamd_dkim_cached_hash *
rspamd_dkim_check_bh_cached (struct rspamd_dkim_common_ctx *ctx,
		struct rspamd_task *task, gsize bhlen, gboolean is_sign)
{
	gchar typebuf[64];
	struct rspamd_dkim_cached_hash *res;

	rspamd_snprintf (typebuf, sizeof (typebuf),
			RSPAMD_MEMPOOL_DKIM_BH_CACHE "%z_%s_%d_%z",
			bhlen,
			ctx->body_canon_type == DKIM_CANON_RELAXED ? "1" : "0",
			!!is_sign,
			ctx->len);

	res = rspamd_mempool_get_variable (task->task_pool,
			typebuf);

	if (!res) {
		res = rspamd_mempool_alloc0 (task->task_pool, sizeof (*res));
		res->type = rspamd_mempool_strdup (task->task_pool, typebuf);
		rspamd_mempool_set_variable (task->task_pool,
				res->type, res, NULL);
	}

	return res;
}

/**
 * Check task for dkim context using dkim key
 * @param ctx dkim verify context
 * @param key dkim key (from cache or from dns request)
 * @param task task to check
 * @return
 */
struct rspamd_dkim_check_result *
rspamd_dkim_check (rspamd_dkim_context_t *ctx,
	rspamd_dkim_key_t *key,
	struct rspamd_task *task)
{
	const gchar *body_end, *body_start;
	guchar raw_digest[EVP_MAX_MD_SIZE];
	struct rspamd_dkim_cached_hash *cached_bh = NULL;
	EVP_MD_CTX *cpy_ctx = NULL;
	gsize dlen = 0;
	struct rspamd_dkim_check_result *res;
	guint i;
	struct rspamd_dkim_header *dh;
	gint nid;

	g_return_val_if_fail (ctx != NULL,		 NULL);
	g_return_val_if_fail (key != NULL,		 NULL);
	g_return_val_if_fail (task->msg.len > 0, NULL);

	/* First of all find place of body */
	body_end = task->msg.begin + task->msg.len;
	body_start = task->raw_headers_content.body_start;

	res = rspamd_mempool_alloc0 (task->task_pool, sizeof (*res));
	res->ctx = ctx;
	res->selector = ctx->selector;
	res->domain = ctx->domain;
	res->fail_reason = NULL;
	res->short_b = ctx->short_b;
	res->rcode = DKIM_CONTINUE;

	if (!body_start) {
		res->rcode = DKIM_ERROR;
		return res;
	}

	if (ctx->common.type != RSPAMD_DKIM_ARC_SEAL) {
		dlen = EVP_MD_CTX_size (ctx->common.body_hash);
		cached_bh = rspamd_dkim_check_bh_cached (&ctx->common, task,
				dlen, FALSE);

		if (!cached_bh->digest_normal) {
			/* Start canonization of body part */
			if (!rspamd_dkim_canonize_body (&ctx->common, body_start, body_end,
					FALSE)) {
				res->rcode = DKIM_RECORD_ERROR;
				return res;
			}
		}
	}

	/* Now canonize headers */
	for (i = 0; i < ctx->common.hlist->len; i++) {
		dh = g_ptr_array_index (ctx->common.hlist, i);
		rspamd_dkim_canonize_header (&ctx->common, task, dh->name, dh->count,
				NULL, NULL);
	}

	/* Canonize dkim signature */
	switch (ctx->common.type) {
	case RSPAMD_DKIM_NORMAL:
		rspamd_dkim_canonize_header (&ctx->common, task, RSPAMD_DKIM_SIGNHEADER, 0,
				ctx->dkim_header, ctx->domain);
		break;
	case RSPAMD_DKIM_ARC_SIG:
		rspamd_dkim_canonize_header (&ctx->common, task, RSPAMD_DKIM_ARC_SIGNHEADER, 0,
				ctx->dkim_header, ctx->domain);
		break;
	case RSPAMD_DKIM_ARC_SEAL:
		rspamd_dkim_canonize_header (&ctx->common, task, RSPAMD_DKIM_ARC_SEALHEADER, 0,
				ctx->dkim_header, ctx->domain);
		break;
	}


	if (ctx->common.type != RSPAMD_DKIM_ARC_SEAL) {
		if (!cached_bh->digest_normal) {
			/* Copy md_ctx to deal with broken CRLF at the end */
			cpy_ctx = EVP_MD_CTX_create ();
			EVP_MD_CTX_copy (cpy_ctx, ctx->common.body_hash);
			EVP_DigestFinal_ex (cpy_ctx, raw_digest, NULL);

			cached_bh->digest_normal = rspamd_mempool_alloc (task->task_pool,
				sizeof (raw_digest));
			memcpy (cached_bh->digest_normal, raw_digest, sizeof (raw_digest));
		}

		/* Check bh field */
		if (memcmp (ctx->bh, cached_bh->digest_normal, ctx->bhlen) != 0) {
			if (cpy_ctx) {
				msg_debug_dkim (
						"bh value mismatch: %*xs versus %*xs, try add CRLF",
						dlen, ctx->bh,
						dlen, cached_bh->digest_normal);
				/* Try add CRLF */
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
				EVP_MD_CTX_cleanup (cpy_ctx);
#else
				EVP_MD_CTX_reset (cpy_ctx);
#endif
				EVP_MD_CTX_copy (cpy_ctx, ctx->common.body_hash);
				EVP_DigestUpdate (cpy_ctx, "\r\n", 2);
				EVP_DigestFinal_ex (cpy_ctx, raw_digest, NULL);
				cached_bh->digest_crlf = rspamd_mempool_alloc (task->task_pool,
						sizeof (raw_digest));
				memcpy (cached_bh->digest_crlf, raw_digest, sizeof (raw_digest));

				if (memcmp (ctx->bh, raw_digest, ctx->bhlen) != 0) {
					msg_debug_dkim (
							"bh value mismatch: %*xs versus %*xs, try add LF",
							dlen, ctx->bh,
							dlen, raw_digest);

					/* Try add LF */
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
					EVP_MD_CTX_cleanup (cpy_ctx);
#else
					EVP_MD_CTX_reset (cpy_ctx);
#endif
					EVP_MD_CTX_copy (cpy_ctx, ctx->common.body_hash);
					EVP_DigestUpdate (cpy_ctx, "\n", 1);
					EVP_DigestFinal_ex (cpy_ctx, raw_digest, NULL);
					cached_bh->digest_cr = rspamd_mempool_alloc (task->task_pool,
							sizeof (raw_digest));
					memcpy (cached_bh->digest_cr, raw_digest, sizeof (raw_digest));

					if (memcmp (ctx->bh, raw_digest, ctx->bhlen) != 0) {
						msg_debug_dkim ("bh value mismatch: %*xs versus %*xs",
								dlen, ctx->bh,
								dlen, raw_digest);
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
						EVP_MD_CTX_cleanup (cpy_ctx);
#else
						EVP_MD_CTX_reset (cpy_ctx);
#endif
						res->fail_reason = "body hash did not verify";
						res->rcode = DKIM_REJECT;
						EVP_MD_CTX_destroy (cpy_ctx);

						return res;
					}
				}
			}
			else if (cached_bh->digest_crlf) {
				if (memcmp (ctx->bh, cached_bh->digest_crlf, ctx->bhlen) != 0) {
					msg_debug_dkim ("bh value mismatch: %*xs versus %*xs",
							dlen, ctx->bh,
							dlen, cached_bh->digest_crlf);

					if (cached_bh->digest_cr) {
						if (memcmp (ctx->bh, cached_bh->digest_cr, ctx->bhlen) != 0) {
							msg_debug_dkim (
									"bh value mismatch: %*xs versus %*xs",
									dlen, ctx->bh,
									dlen, cached_bh->digest_cr);

							res->fail_reason = "body hash did not verify";
							res->rcode = DKIM_REJECT;

							return res;
						}
					}
					else {

						res->fail_reason = "body hash did not verify";
						res->rcode = DKIM_REJECT;

						return res;
					}
				}
			}
			else {
				msg_debug_dkim (
						"bh value mismatch: %*xs versus %*xs",
						dlen, ctx->bh,
						dlen, cached_bh->digest_normal);
				res->fail_reason = "body hash did not verify";
				res->rcode = DKIM_REJECT;

				return res;
			}
		}

		if (cpy_ctx) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
			EVP_MD_CTX_cleanup (cpy_ctx);
#else
			EVP_MD_CTX_reset (cpy_ctx);
#endif
			EVP_MD_CTX_destroy (cpy_ctx);
		}
	}

	dlen = EVP_MD_CTX_size (ctx->common.headers_hash);
	EVP_DigestFinal_ex (ctx->common.headers_hash, raw_digest, NULL);
	/* Check headers signature */

	if (ctx->sig_alg == DKIM_SIGN_RSASHA1) {
		nid = NID_sha1;
	}
	else if (ctx->sig_alg == DKIM_SIGN_RSASHA256 ||
			ctx->sig_alg == DKIM_SIGN_ECDSASHA256 ||
			ctx->sig_alg == DKIM_SIGN_EDDSASHA256) {
		nid = NID_sha256;
	}
	else if (ctx->sig_alg == DKIM_SIGN_RSASHA512 ||
			ctx->sig_alg == DKIM_SIGN_ECDSASHA512) {
		nid = NID_sha512;
	}
	else {
		/* Not reached */
		nid = NID_sha1;
	}

	switch (key->type) {
	case RSPAMD_DKIM_KEY_RSA:
		if (RSA_verify (nid, raw_digest, dlen, ctx->b, ctx->blen,
				key->key.key_rsa) != 1) {
			msg_debug_dkim ("rsa verify failed");
			res->rcode = DKIM_REJECT;
			res->fail_reason = "rsa verify failed";
		}
		break;
	case RSPAMD_DKIM_KEY_ECDSA:
		if (ECDSA_verify (nid, raw_digest, dlen, ctx->b, ctx->blen,
				key->key.key_ecdsa) != 1) {
			msg_debug_dkim ("ecdsa verify failed");
			res->rcode = DKIM_REJECT;
			res->fail_reason = "ecdsa verify failed";
		}
		break;
	case RSPAMD_DKIM_KEY_EDDSA:
		if (!rspamd_cryptobox_verify (ctx->b, ctx->blen, raw_digest, dlen,
				key->key.key_eddsa, RSPAMD_CRYPTOBOX_MODE_25519)) {
			msg_debug_dkim ("eddsa verify failed");
			res->rcode = DKIM_REJECT;
			res->fail_reason = "eddsa verify failed";
		}
		break;
	}


	if (ctx->common.type == RSPAMD_DKIM_ARC_SEAL && res == DKIM_CONTINUE) {
		switch (ctx->cv) {
		case RSPAMD_ARC_INVALID:
			msg_info_dkim ("arc seal is invalid i=%d", ctx->common.idx);
			res->rcode = DKIM_PERM_ERROR;
			res->fail_reason = "arc seal is invalid";
			break;
		case RSPAMD_ARC_FAIL:
			msg_info_dkim ("arc seal failed i=%d", ctx->common.idx);
			res->rcode = DKIM_REJECT;
			res->fail_reason = "arc seal failed";
			break;
		default:
			break;
		}
	}

	return res;
}

struct rspamd_dkim_check_result *
rspamd_dkim_create_result (rspamd_dkim_context_t *ctx,
						   enum rspamd_dkim_check_rcode rcode,
						   struct rspamd_task *task)
{
	struct rspamd_dkim_check_result *res;

	res = rspamd_mempool_alloc0 (task->task_pool, sizeof (*res));
	res->ctx = ctx;
	res->selector = ctx->selector;
	res->domain = ctx->domain;
	res->fail_reason = NULL;
	res->short_b = ctx->short_b;
	res->rcode = rcode;

	return res;
}

rspamd_dkim_key_t *
rspamd_dkim_key_ref (rspamd_dkim_key_t *k)
{
	REF_RETAIN (k);

	return k;
}

void
rspamd_dkim_key_unref (rspamd_dkim_key_t *k)
{
	REF_RELEASE (k);
}

rspamd_dkim_sign_key_t *
rspamd_dkim_sign_key_ref (rspamd_dkim_sign_key_t *k)
{
	REF_RETAIN (k);

	return k;
}

void
rspamd_dkim_sign_key_unref (rspamd_dkim_sign_key_t *k)
{
	REF_RELEASE (k);
}

const gchar*
rspamd_dkim_get_domain (rspamd_dkim_context_t *ctx)
{
	if (ctx) {
		return ctx->domain;
	}

	return NULL;
}

const gchar*
rspamd_dkim_get_selector (rspamd_dkim_context_t *ctx)
{
	if (ctx) {
		return ctx->selector;
	}

	return NULL;
}

guint
rspamd_dkim_key_get_ttl (rspamd_dkim_key_t *k)
{
	if (k) {
		return k->ttl;
	}

	return 0;
}

const gchar*
rspamd_dkim_get_dns_key (rspamd_dkim_context_t *ctx)
{
	if (ctx) {
		return ctx->dns_key;
	}

	return NULL;
}

rspamd_dkim_sign_key_t*
rspamd_dkim_sign_key_load (const gchar *what, gsize len,
		enum rspamd_dkim_sign_key_type type,
		GError **err)
{
	gpointer map;
	gsize map_len = 0;
	rspamd_dkim_sign_key_t *nkey;
	struct stat st;
	time_t mtime = 0;

	if (type == RSPAMD_DKIM_SIGN_KEY_FILE) {
		gchar fpath[PATH_MAX];

		rspamd_snprintf (fpath, sizeof (fpath), "%*s", (gint)len, what);

		if (stat (fpath, &st) == -1) {
			g_set_error (err, dkim_error_quark (), DKIM_SIGERROR_KEYFAIL,
					"cannot stat private key %s: %s",
					fpath, strerror (errno));

			return NULL;
		}

		mtime = st.st_mtime;
		map = rspamd_file_xmap (fpath, PROT_READ, &map_len, TRUE);

		if (map == NULL) {
			g_set_error (err, dkim_error_quark (), DKIM_SIGERROR_KEYFAIL,
					"cannot map private key %s: %s",
					fpath, strerror (errno));

			return NULL;
		}
	}

	nkey = g_malloc0 (sizeof (*nkey));
	nkey->type = type;
	nkey->mtime = mtime;

	switch (type) {
	case RSPAMD_DKIM_SIGN_KEY_FILE:
		(void)mlock (map, len);
		nkey->keydata = map;
		nkey->keylen = map_len;
		break;
	case RSPAMD_DKIM_SIGN_KEY_BASE64:
		nkey->keydata = g_malloc (len);
		nkey->keylen = len;
		rspamd_cryptobox_base64_decode (what, len, nkey->keydata,
				&nkey->keylen);
		break;
	case RSPAMD_DKIM_SIGN_KEY_DER:
	case RSPAMD_DKIM_SIGN_KEY_PEM:
		nkey->keydata = g_malloc (len);
		memcpy (nkey->keydata, what, len);
		nkey->keylen = len;
	}

	(void)mlock (nkey->keydata, nkey->keylen);
	nkey->key_bio = BIO_new_mem_buf (nkey->keydata, nkey->keylen);

	if (type == RSPAMD_DKIM_SIGN_KEY_DER || type == RSPAMD_DKIM_SIGN_KEY_BASE64) {
		if (d2i_PrivateKey_bio (nkey->key_bio, &nkey->key_evp) == NULL) {
			if (type == RSPAMD_DKIM_SIGN_KEY_FILE) {
				g_set_error (err, dkim_error_quark (), DKIM_SIGERROR_KEYFAIL,
						"cannot read private key from %*s: %s",
						(gint)len, what,
						ERR_error_string (ERR_get_error (), NULL));
			}
			else {
				g_set_error (err, dkim_error_quark (), DKIM_SIGERROR_KEYFAIL,
						"cannot read private key from string: %s",
						ERR_error_string (ERR_get_error (), NULL));
			}

			rspamd_dkim_sign_key_free (nkey);

			return NULL;
		}
	}
	else {
		if (!PEM_read_bio_PrivateKey (nkey->key_bio, &nkey->key_evp, NULL, NULL)) {
			if (type == RSPAMD_DKIM_SIGN_KEY_FILE) {
				g_set_error (err, dkim_error_quark (), DKIM_SIGERROR_KEYFAIL,
						"cannot read private key from %*s: %s",
						(gint)len, what,
						ERR_error_string (ERR_get_error (), NULL));
			}
			else {
				g_set_error (err, dkim_error_quark (), DKIM_SIGERROR_KEYFAIL,
						"cannot read private key from string: %s",
						ERR_error_string (ERR_get_error (), NULL));
			}

			rspamd_dkim_sign_key_free (nkey);

			return NULL;
		}
	}

	nkey->key_rsa = EVP_PKEY_get1_RSA (nkey->key_evp);
	if (nkey->key_rsa == NULL) {
		g_set_error (err,
				DKIM_ERROR,
				DKIM_SIGERROR_KEYFAIL,
				"cannot extract rsa key from evp key");
		rspamd_dkim_sign_key_free (nkey);

		return NULL;
	}

	REF_INIT_RETAIN (nkey, rspamd_dkim_sign_key_free);

	return nkey;
}

gboolean
rspamd_dkim_sign_key_maybe_invalidate (rspamd_dkim_sign_key_t *key,
		enum rspamd_dkim_sign_key_type type,
		const gchar *what, gsize len)
{
	struct stat st;

	if (type == RSPAMD_DKIM_SIGN_KEY_FILE) {
		gchar fpath[PATH_MAX];

		rspamd_snprintf (fpath, sizeof (fpath), "%*s", (gint) len, what);

		if (stat (fpath, &st) == -1) {
			/* Prefer to use cached key since it is absent on FS */
			return FALSE;
		}

		if (st.st_mtime > key->mtime) {
			return TRUE;
		}
	}

	return FALSE;
}

rspamd_dkim_sign_context_t *
rspamd_create_dkim_sign_context (struct rspamd_task *task,
		rspamd_dkim_sign_key_t *priv_key,
		gint headers_canon,
		gint body_canon,
		const gchar *headers,
		enum rspamd_dkim_type type,
		GError **err)
{
	rspamd_dkim_sign_context_t *nctx;

	if (headers_canon != DKIM_CANON_SIMPLE && headers_canon != DKIM_CANON_RELAXED) {
		g_set_error (err,
				DKIM_ERROR,
				DKIM_SIGERROR_INVALID_HC,
				"bad headers canonicalisation");

		return NULL;
	}
	if (body_canon != DKIM_CANON_SIMPLE && body_canon != DKIM_CANON_RELAXED) {
		g_set_error (err,
				DKIM_ERROR,
				DKIM_SIGERROR_INVALID_BC,
				"bad body canonicalisation");

		return NULL;
	}

	if (!priv_key || !priv_key->key_rsa) {
		g_set_error (err,
				DKIM_ERROR,
				DKIM_SIGERROR_KEYFAIL,
				"bad key to sign");

		return NULL;
	}

	nctx = rspamd_mempool_alloc0 (task->task_pool, sizeof (*nctx));
	nctx->common.pool = task->task_pool;
	nctx->common.header_canon_type = headers_canon;
	nctx->common.body_canon_type = body_canon;
	nctx->common.type = type;

	if (type != RSPAMD_DKIM_ARC_SEAL) {
		if (!rspamd_dkim_parse_hdrlist_common (&nctx->common, headers,
				strlen (headers), TRUE,
				err)) {
			return NULL;
		}
	}
	else {
		rspamd_dkim_add_arc_seal_headers (task->task_pool, &nctx->common);
	}

	nctx->key = rspamd_dkim_sign_key_ref (priv_key);

	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t)rspamd_dkim_sign_key_unref, priv_key);

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	nctx->common.body_hash = EVP_MD_CTX_create ();
	EVP_DigestInit_ex (nctx->common.body_hash, EVP_sha256 (), NULL);
	nctx->common.headers_hash = EVP_MD_CTX_create ();
	EVP_DigestInit_ex (nctx->common.headers_hash, EVP_sha256 (), NULL);
	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t)EVP_MD_CTX_destroy, nctx->common.body_hash);
	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t)EVP_MD_CTX_destroy, nctx->common.headers_hash);
#else
	nctx->common.body_hash = EVP_MD_CTX_new ();
	EVP_DigestInit_ex (nctx->common.body_hash, EVP_sha256 (), NULL);
	nctx->common.headers_hash = EVP_MD_CTX_new ();
	EVP_DigestInit_ex (nctx->common.headers_hash, EVP_sha256 (), NULL);
	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t)EVP_MD_CTX_free, nctx->common.body_hash);
	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t)EVP_MD_CTX_free, nctx->common.headers_hash);
#endif

	return nctx;
}


GString *
rspamd_dkim_sign (struct rspamd_task *task, const gchar *selector,
		const gchar *domain, time_t expire, gsize len, guint idx,
		const gchar *arc_cv, rspamd_dkim_sign_context_t *ctx)
{
	GString *hdr;
	struct rspamd_dkim_header *dh;
	const gchar *body_end, *body_start, *hname;
	guchar raw_digest[EVP_MAX_MD_SIZE];
	struct rspamd_dkim_cached_hash *cached_bh = NULL;
	gsize dlen = 0;
	guint i, j;
	gchar *b64_data;
	guchar *rsa_buf;
	guint rsa_len;
	guint headers_len = 0, cur_len = 0;
	union rspamd_dkim_header_stat hstat;

	g_assert (ctx != NULL);

	/* First of all find place of body */
	body_end = task->msg.begin + task->msg.len;
	body_start = task->raw_headers_content.body_start;

	if (len > 0) {
		ctx->common.len = len;
	}

	if (!body_start) {
		return NULL;
	}

	/* Start canonization of body part */
	if (ctx->common.type != RSPAMD_DKIM_ARC_SEAL) {
		dlen = EVP_MD_CTX_size (ctx->common.body_hash);
		cached_bh = rspamd_dkim_check_bh_cached (&ctx->common, task,
				dlen, TRUE);

		if (!cached_bh->digest_normal) {
			/* Start canonization of body part */
			if (!rspamd_dkim_canonize_body (&ctx->common, body_start, body_end,
					TRUE)) {
				return NULL;
			}
		}
	}

	hdr = g_string_sized_new (255);

	if (ctx->common.type == RSPAMD_DKIM_NORMAL) {
		rspamd_printf_gstring (hdr, "v=1; a=rsa-sha256; c=%s/%s; d=%s; s=%s; ",
				ctx->common.header_canon_type == DKIM_CANON_RELAXED ?
						"relaxed" : "simple",
				ctx->common.body_canon_type == DKIM_CANON_RELAXED ?
						"relaxed" : "simple",
				domain, selector);
	}
	else if (ctx->common.type == RSPAMD_DKIM_ARC_SIG) {
		rspamd_printf_gstring (hdr, "i=%d; a=rsa-sha256; c=%s/%s; d=%s; s=%s; ",
				idx,
				ctx->common.header_canon_type == DKIM_CANON_RELAXED ?
						"relaxed" : "simple",
				ctx->common.body_canon_type == DKIM_CANON_RELAXED ?
						"relaxed" : "simple",
				domain, selector);
	}
	else {
		g_assert (arc_cv != NULL);
		rspamd_printf_gstring (hdr, "i=%d; a=rsa-sha256; c=%s/%s; d=%s; s=%s; cv=%s; ",
				arc_cv,
				idx,
				domain, selector);
	}

	if (expire > 0) {
		rspamd_printf_gstring (hdr, "x=%t; ", expire);
	}

	if (ctx->common.type != RSPAMD_DKIM_ARC_SEAL) {
		if (len > 0) {
			rspamd_printf_gstring (hdr, "l=%z; ", len);
		}
	}

	rspamd_printf_gstring (hdr, "t=%t; h=", time (NULL));

	/* Now canonize headers */
	for (i = 0; i < ctx->common.hlist->len; i++) {
		dh = g_ptr_array_index (ctx->common.hlist, i);

		/* We allow oversigning if dh->count > number of headers with this name */
		hstat.n = GPOINTER_TO_UINT (g_hash_table_lookup (ctx->common.htable, dh->name));

		if (hstat.s.flags & RSPAMD_DKIM_FLAG_OVERSIGN) {
			/* Do oversigning */
			GPtrArray *ar;
			guint count = 0;

			ar = g_hash_table_lookup (task->raw_headers, dh->name);

			if (ar) {
				count = ar->len;
			}

			for (j = 0; j < count; j ++) {
				/* Sign all existing headers */
				rspamd_dkim_canonize_header (&ctx->common, task, dh->name, j,
						NULL, NULL);
			}

			/* Now add one more entry to oversign */
			cur_len = (strlen (dh->name) + 1) * (count + 1);
			headers_len += cur_len;
			if (headers_len > 70 && i > 0 && i < ctx->common.hlist->len - 1) {
				rspamd_printf_gstring (hdr, "  ");
				headers_len = cur_len;
			}

			for (j = 0; j < count + 1; j++) {
				rspamd_printf_gstring (hdr, "%s:", dh->name);
			}
		}
		else {
			if (g_hash_table_lookup (task->raw_headers, dh->name)) {
				if (hstat.s.count > 0) {

					cur_len = (strlen (dh->name) + 1) * (hstat.s.count);
					headers_len += cur_len;
					if (headers_len > 70 && i > 0 && i < ctx->common.hlist->len - 1) {
						rspamd_printf_gstring (hdr, "  ");
						headers_len = cur_len;
					}

					for (j = 0; j < hstat.s.count; j++) {
						rspamd_printf_gstring (hdr, "%s:", dh->name);
					}
				}


				rspamd_dkim_canonize_header (&ctx->common, task,
						dh->name, dh->count,
						NULL, NULL);
			}
		}

		g_hash_table_remove (ctx->common.htable, dh->name);
	}

	/* Replace the last ':' with ';' */
	hdr->str[hdr->len - 1] = ';';

	if (ctx->common.type != RSPAMD_DKIM_ARC_SEAL) {
		if (!cached_bh->digest_normal) {
			EVP_DigestFinal_ex (ctx->common.body_hash, raw_digest, NULL);
			cached_bh->digest_normal = rspamd_mempool_alloc (task->task_pool,
					sizeof (raw_digest));
			memcpy (cached_bh->digest_normal, raw_digest, sizeof (raw_digest));
		}


		b64_data = rspamd_encode_base64 (cached_bh->digest_normal, dlen, 0, NULL);
		rspamd_printf_gstring (hdr, " bh=%s; b=", b64_data);
		g_free (b64_data);
	}
	else {
		rspamd_printf_gstring (hdr, " b=");
	}

	switch (ctx->common.type) {
	case RSPAMD_DKIM_NORMAL:
	default:
		hname = RSPAMD_DKIM_SIGNHEADER;
		break;
	case RSPAMD_DKIM_ARC_SIG:
		hname = RSPAMD_DKIM_ARC_SIGNHEADER;
		break;
	case RSPAMD_DKIM_ARC_SEAL:
		hname = RSPAMD_DKIM_ARC_SEALHEADER;
		break;
	}

	if (ctx->common.header_canon_type == DKIM_CANON_RELAXED) {
		if (!rspamd_dkim_canonize_header_relaxed (&ctx->common,
				hdr->str,
				hname,
				TRUE)) {

			g_string_free (hdr, TRUE);
			return NULL;
		}
	}
	else {
		/* Will likely have issues with folding */
		rspamd_dkim_hash_update (ctx->common.headers_hash, hdr->str,
				hdr->len);
		msg_debug_task ("update signature with header: %*s",
				(gint)hdr->len, hdr->str);
	}

	dlen = EVP_MD_CTX_size (ctx->common.headers_hash);
	EVP_DigestFinal_ex (ctx->common.headers_hash, raw_digest, NULL);
	rsa_len = RSA_size (ctx->key->key_rsa);
	rsa_buf = g_alloca (rsa_len);

	if (RSA_sign (NID_sha256, raw_digest, dlen, rsa_buf, &rsa_len,
			ctx->key->key_rsa) != 1) {
		g_string_free (hdr, TRUE);
		msg_err_task ("rsa sign error: %s",
				ERR_error_string (ERR_get_error (), NULL));

		return NULL;
	}

	if (task->flags & RSPAMD_TASK_FLAG_MILTER) {
		b64_data = rspamd_encode_base64_fold (rsa_buf, rsa_len, 70, NULL,
				RSPAMD_TASK_NEWLINES_LF);
	}
	else {
		b64_data = rspamd_encode_base64_fold (rsa_buf, rsa_len, 70, NULL,
				task->nlines_type);
	}

	rspamd_printf_gstring (hdr, "%s", b64_data);
	g_free (b64_data);

	return hdr;
}

gboolean
rspamd_dkim_match_keys (rspamd_dkim_key_t *pk,
								 rspamd_dkim_sign_key_t *sk,
								 GError **err)
{
	const BIGNUM *n1, *n2;

	if (pk == NULL || sk == NULL) {
		g_set_error (err, dkim_error_quark (), DKIM_SIGERROR_KEYFAIL,
				"missing public or private key");
		return FALSE;
	}

	if (pk->type != RSPAMD_DKIM_KEY_RSA) {
		g_set_error (err, dkim_error_quark (), DKIM_SIGERROR_KEYFAIL,
				"pubkey is not RSA key");
		return FALSE;
	}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	RSA_get0_key (pk->key.key_rsa, &n1, NULL, NULL);
	RSA_get0_key (sk->key_rsa, &n2, NULL, NULL);
#else
	n1 = pk->key.key_rsa->n;
	n2 = sk->key_rsa->n;
#endif

	if (BN_cmp (n1, n2) != 0) {
		g_set_error (err, dkim_error_quark (), DKIM_SIGERROR_KEYHASHMISMATCH,
				"pubkey does not match private key");
		return FALSE;
	}

	return TRUE;
}