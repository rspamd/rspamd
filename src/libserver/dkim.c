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

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <sys/mman.h>

/* special DNS tokens */
#define DKIM_DNSKEYNAME     "_domainkey"

/* Canonization methods */
#define DKIM_CANON_UNKNOWN  (-1)    /* unknown method */
#define DKIM_CANON_SIMPLE   0   /* as specified in DKIM spec */
#define DKIM_CANON_RELAXED  1   /* as specified in DKIM spec */

#define DKIM_CANON_DEFAULT  DKIM_CANON_SIMPLE

/* Params */
#define DKIM_PARAM_UNKNOWN  (-1)    /* unknown */
#define DKIM_PARAM_SIGNATURE    0   /* b */
#define DKIM_PARAM_SIGNALG  1   /* a */
#define DKIM_PARAM_DOMAIN   2   /* d */
#define DKIM_PARAM_CANONALG 3   /* c */
#define DKIM_PARAM_QUERYMETHOD  4   /* q */
#define DKIM_PARAM_SELECTOR 5   /* s */
#define DKIM_PARAM_HDRLIST  6   /* h */
#define DKIM_PARAM_VERSION  7   /* v */
#define DKIM_PARAM_IDENTITY 8   /* i */
#define DKIM_PARAM_TIMESTAMP    9   /* t */
#define DKIM_PARAM_EXPIRATION   10  /* x */
#define DKIM_PARAM_COPIEDHDRS   11  /* z */
#define DKIM_PARAM_BODYHASH 12  /* bh */
#define DKIM_PARAM_BODYLENGTH   13  /* l */

/* Signature methods */
#define DKIM_SIGN_UNKNOWN   (-2)    /* unknown method */
#define DKIM_SIGN_DEFAULT   (-1)    /* use internal default */
#define DKIM_SIGN_RSASHA1   0   /* an RSA-signed SHA1 digest */
#define DKIM_SIGN_RSASHA256 1   /* an RSA-signed SHA256 digest */

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
#define msg_debug_dkim(...)  rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
        "dkim", ctx->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)



struct rspamd_dkim_common_ctx {
	rspamd_mempool_t *pool;
	gsize len;
	gint header_canon_type;
	gint body_canon_type;
	GPtrArray *hlist;
	EVP_MD_CTX *headers_hash;
	EVP_MD_CTX *body_hash;
};

struct rspamd_dkim_context_s {
	struct rspamd_dkim_common_ctx common;
	rspamd_mempool_t *pool;
	gint sig_alg;
	guint bhlen;
	guint blen;
	guint ver;
	time_t timestamp;
	time_t expiration;
	gchar *domain;
	gchar *selector;
	gint8 *b;
	gint8 *bh;
	gchar *dns_key;
	const gchar *dkim_header;
};

struct rspamd_dkim_key_s {
	guint8 *keydata;
	guint keylen;
	gsize decoded_len;
	guint ttl;
	RSA *key_rsa;
	BIO *key_bio;
	EVP_PKEY *key_evp;
	ref_entry_t ref;
};

struct rspamd_dkim_sign_context_s {
	struct rspamd_dkim_common_ctx common;
	rspamd_dkim_sign_key_t *key;
};

struct rspamd_dkim_sign_key_s {
	guint8 *keydata;
	guint keylen;
	RSA *key_rsa;
	BIO *key_bio;
	EVP_PKEY *key_evp;
	ref_entry_t ref;
};


struct rspamd_dkim_header {
	gchar *name;
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
	[DKIM_PARAM_BODYLENGTH] = rspamd_dkim_parse_bodylength
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
	ctx->b = rspamd_mempool_alloc (ctx->pool, len + 1);
	rspamd_strlcpy (ctx->b, param, len + 1);
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 20))
	gchar *tmp;
	gsize tmp_len = len;
	tmp = g_base64_decode (ctx->b, &tmp_len);
	rspamd_strlcpy (ctx->b, tmp, tmp_len + 1);
	g_free (tmp);
#else
	g_base64_decode_inplace (ctx->b, &len);
#endif
	ctx->blen = len;
	return TRUE;
}

static gboolean
rspamd_dkim_parse_signalg (rspamd_dkim_context_t * ctx,
	const gchar *param,
	gsize len,
	GError **err)
{
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
	GError **err)
{
	const gchar *c, *p, *end = param + len;
	gchar *h;
	gboolean from_found = FALSE;
	guint count = 0;
	struct rspamd_dkim_header *new;
	GHashTable *htb;

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
	htb = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);

	while (p <= end) {
		if ((p == end || *p == ':') && p - c > 0) {
			h = rspamd_mempool_alloc (ctx->pool, p - c + 1);
			rspamd_strlcpy (h, c, p - c + 1);
			g_strstrip (h);

			if ((new = g_hash_table_lookup (htb, h)) != NULL) {
				new->count++;
			}
			else {
				/* Insert new header to the list */
				new =
					rspamd_mempool_alloc (ctx->pool,
						sizeof (struct rspamd_dkim_header));
				new->name = h;
				new->count = 1;
				g_hash_table_insert (htb, new->name, new);

				/* Check mandatory from */
				if (!from_found && g_ascii_strcasecmp (h, "from") == 0) {
					from_found = TRUE;
				}

				g_ptr_array_add (ctx->hlist, new);
			}
			c = p + 1;
			p++;
		}
		else {
			p++;
		}
	}

	g_hash_table_unref (htb);

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
		/* Reverse list */
		rspamd_mempool_add_destructor (ctx->pool,
			(rspamd_mempool_destruct_t)rspamd_dkim_hlist_free,
			ctx->hlist);
	}

	return TRUE;
}

static gboolean
rspamd_dkim_parse_hdrlist (rspamd_dkim_context_t *ctx,
	const gchar *param,
	gsize len,
	GError **err)
{
	return rspamd_dkim_parse_hdrlist_common (&ctx->common, param, len, err);
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
	ctx->bh = rspamd_mempool_alloc (ctx->pool, len + 1);
	rspamd_strlcpy (ctx->bh, param, len + 1);
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 20))
	gchar *tmp;
	gsize tmp_len = len;
	tmp = g_base64_decode (ctx->bh, &tmp_len);
	rspamd_strlcpy (ctx->bh, tmp, tmp_len + 1);
	g_free (tmp);
#else
	g_base64_decode_inplace (ctx->bh, &len);
#endif
	ctx->bhlen = len;
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
	ctx->common.header_canon_type = DKIM_CANON_DEFAULT;
	ctx->common.body_canon_type = DKIM_CANON_DEFAULT;
	ctx->sig_alg = DKIM_SIGN_UNKNOWN;
	ctx->common.pool = pool;
	/* A simple state machine of parsing tags */
	state = DKIM_STATE_SKIP_SPACES;
	next_state = DKIM_STATE_TAG;
	taglen = 0;
	p = sig;
	c = sig;
	end = p + strlen (p);

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
					param = DKIM_PARAM_VERSION;
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
					param = DKIM_PARAM_HDRLIST;
					break;
				case 'i':
					param = DKIM_PARAM_IDENTITY;
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
					param = DKIM_PARAM_BODYHASH;
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
					!parser_funcs[param](ctx, c, p - c + 1, err)) {
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
				msg_info_dkim ("dkim parse failed: unknown error");
				return NULL;
			}
			break;
		}
	}

	/* Now check validity of signature */
	if (ctx->b == NULL) {
		g_set_error (err,
			DKIM_ERROR,
			DKIM_SIGERROR_EMPTY_B,
			"b parameter missing");
		return NULL;
	}
	if (ctx->bh == NULL) {
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
	if (ctx->ver == 0) {
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
	if (ctx->sig_alg == DKIM_SIGN_RSASHA1) {
		/* Check bh length */
		if (ctx->bhlen != (guint)EVP_MD_size (EVP_sha1 ())) {
			g_set_error (err,
				DKIM_ERROR,
				DKIM_SIGERROR_BADSIG,
				"signature has incorrect length: %u",
				ctx->bhlen);
			return NULL;
		}

	}
	else if (ctx->sig_alg == DKIM_SIGN_RSASHA256) {
		if (ctx->bhlen !=
			(guint)EVP_MD_size (EVP_sha256 ())) {
			g_set_error (err,
				DKIM_ERROR,
				DKIM_SIGERROR_BADSIG,
				"signature has incorrect length: %u",
				ctx->bhlen);
			return NULL;
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
	else if (ctx->sig_alg == DKIM_SIGN_RSASHA256) {
		md_alg = EVP_sha256 ();
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

static rspamd_dkim_key_t *
rspamd_dkim_make_key (rspamd_dkim_context_t *ctx, const gchar *keydata,
		guint keylen, GError **err)
{
	rspamd_dkim_key_t *key = NULL;

	if (keylen < 3) {
		msg_err_dkim ("DKIM key is too short to be valid");
		return NULL;
	}

	key = g_slice_alloc0 (sizeof (rspamd_dkim_key_t));
	key->keydata = g_slice_alloc (keylen + 1);
	rspamd_strlcpy (key->keydata, keydata, keylen + 1);
	key->keylen = keylen + 1;
	key->decoded_len = keylen + 1;
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 20))
	gchar *tmp;
	gsize tmp_len = keylen;
	tmp = g_base64_decode (key->keydata, &tmp_len);
	rspamd_strlcpy (key->keydata, tmp, tmp_len + 1);
	g_free (tmp);
	key->decoded_len = tmp_len;
#else
	g_base64_decode_inplace (key->keydata, &key->decoded_len);
#endif
	REF_INIT_RETAIN (key, rspamd_dkim_key_free);

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

	key->key_rsa = EVP_PKEY_get1_RSA (key->key_evp);
	if (key->key_rsa == NULL) {
		g_set_error (err,
			DKIM_ERROR,
			DKIM_SIGERROR_KEYFAIL,
			"cannot extract rsa key from evp key");
		REF_RELEASE (key);

		return NULL;
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
	if (key->key_rsa) {
		RSA_free (key->key_rsa);
	}
	if (key->key_bio) {
		BIO_free (key->key_bio);
	}

	g_slice_free1 (key->keylen,				   key->keydata);
	g_slice_free1 (sizeof (rspamd_dkim_key_t), key);
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
		munmap (key->keydata, key->keylen);
	}

	g_slice_free1 (sizeof (rspamd_dkim_sign_key_t), key);
}

static rspamd_dkim_key_t *
rspamd_dkim_parse_key (rspamd_dkim_context_t *ctx, const gchar *txt,
		gsize *keylen, GError **err)
{
	const gchar *c, *p, *end;
	gint state = 0;
	gsize len;

	c = txt;
	p = txt;
	end = txt + strlen (txt);

	while (p <= end) {
		switch (state) {
		case 0:
			if (p != end && p[0] == 'p' && p[1] == '=') {
				/* We got something like public key */
				c = p + 2;
				p = c;
				state = 1;
			}
			else {
				/* Ignore everything */
				p++;
			}
			break;
		case 1:
			/* State when we got p= and looking for some public key */
			if ((*p == ';' || p == end) && p > c) {
				len = p - c;

				if (keylen) {
					*keylen = len;
				}

				return rspamd_dkim_make_key (ctx, c, len, err);
			}
			else {
				p++;
			}
			break;
		}
	}

	if (p - c == 0) {
		g_set_error (err,
			DKIM_ERROR,
			DKIM_SIGERROR_KEYREVOKED,
			"key was revoked");
	}
	else {
		g_set_error (err, DKIM_ERROR, DKIM_SIGERROR_KEYFAIL,
			"key was not found");
	}

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
		g_set_error (&err,
			DKIM_ERROR,
			DKIM_SIGERROR_NOKEY,
			"dns request to %s failed: %s",
			cbdata->ctx->dns_key,
			rdns_strerror (reply->code));
		cbdata->handler (NULL, 0, cbdata->ctx, cbdata->ud, err);
	}
	else {
		LL_FOREACH (reply->entries, elt)
		{
			if (elt->type == RDNS_REQUEST_TXT) {
				key = rspamd_dkim_parse_key (cbdata->ctx, elt->content.txt.data,
						&keylen,
						&err);
				if (key) {
					key->ttl = elt->ttl;
					break;
				}
			}
		}
		if (key != NULL && err != NULL) {
			/* Free error as it is insignificant */
			g_error_free (err);
			err = NULL;
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
		guint type, gboolean *need_crlf)
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

	while (p >= start + 2) {
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
				if (type == DKIM_CANON_SIMPLE) {
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
			else if (type == DKIM_CANON_RELAXED && *p == ' ') {
				skip = 0;
				state = test_spaces;
			}
			else {
				goto end;
			}
			break;
		case got_cr:
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
			else if (type == DKIM_CANON_RELAXED && *(p - 1) == ' ') {
				skip = 1;
				state = test_spaces;
			}
			else {
				goto end;
			}
			break;
		case got_lf:
			if (*(p - 1) == '\r') {
				state = got_crlf;
			}
			else if (*(p - 1) == '\n') {
				/* We know about one line */
				p --;
				state = got_lf;
			}
			else if (type == DKIM_CANON_RELAXED && *(p - 1) == ' ') {
				skip = 1;
				state = test_spaces;
			}
			else {
				goto end;
			}
			break;
		case got_crlf:
			if (p > start - 2) {
				if (*(p - 3) == '\r') {
					p -= 2;
					state = got_cr;
				}
				else if (*(p - 3) == '\n') {
					p -= 2;
					state = got_lf;
				}
				else if (type == DKIM_CANON_RELAXED && *(p - 3) == ' ') {
					skip = 2;
					state = test_spaces;
				}
				else {
					goto end;
				}
			}
			else {
				goto end;
			}
			break;
		case test_spaces:
			t = p - skip;

			while (t > start - 2 && *t == ' ') {
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
	const gchar *end)
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
		p = rspamd_dkim_skip_empty_lines (start, end, ctx->body_canon_type, &need_crlf);
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
	while (p != end) {
		if (*p == '\r') {
			EVP_DigestUpdate (ck, c,	 p - c);
			EVP_DigestUpdate (ck, CRLF, sizeof (CRLF) - 1);
			p++;
			if (*p == '\n') {
				p++;
			}
			c = p;
		}
		else if (*p == '\n') {
			EVP_DigestUpdate (ck, c,	 p - c);
			EVP_DigestUpdate (ck, CRLF, sizeof (CRLF) - 1);
			p++;
			c = p;
		}
		else {
			p++;
		}
	}
	if (p != c) {
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

static gboolean
rspamd_dkim_canonize_header_relaxed (struct rspamd_dkim_common_ctx *ctx,
	const gchar *header,
	const gchar *header_name,
	gboolean is_sign)
{
	const gchar *h;
	gchar *t, *buf;
	guint inlen;
	gboolean got_sp, allocated = FALSE;

	inlen = strlen (header) + strlen (header_name) + sizeof (":" CRLF);
	if (inlen > BUFSIZ) {
		buf = g_malloc (inlen);
		allocated = TRUE;
	}
	else {
		/* Faster */
		buf = g_alloca (inlen);
	}

	/* Name part */
	t = buf;
	h = header_name;
	while (*h) {
		*t++ = g_ascii_tolower (*h++);
	}
	*t++ = ':';

	/* Value part */
	h = header;
	/* Skip spaces at the beginning */
	while (g_ascii_isspace (*h)) {
		h++;
	}
	got_sp = FALSE;

	while (*h) {
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
	*t++ = '\r';
	*t++ = '\n';
	*t = '\0';

	if (!is_sign) {
		msg_debug_dkim ("update signature with header: %s", buf);
		EVP_DigestUpdate (ctx->headers_hash, buf, t - buf);
	}
	else {
		rspamd_dkim_signature_update (ctx, buf, t - buf);
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
	struct raw_header *rh, *rh_iter;
	guint rh_num = 0;
	guint i;
	GPtrArray *sign_headers;

	if (dkim_header == NULL) {
		rh = g_hash_table_lookup (task->raw_headers, header_name);

		if (rh) {
			LL_FOREACH (rh, rh_iter) {
				rh_num++;
			}

			if (rh_num > count) {
				/* Set skip count */
				rh_num -= count;
			}
			else {
				rh_num = 0;
			}

			sign_headers = g_ptr_array_sized_new (rh_num);
			/* Skip number of headers */
			rh_iter = rh;
			while (rh_num) {
				rh_iter = rh_iter->next;
				rh_num--;
			}

			/* Now insert required headers */
			while (rh_iter) {
				g_ptr_array_add (sign_headers, rh_iter);
				rh_iter = rh_iter->next;
			}

			for (i = 0; i < sign_headers->len; i ++) {
				rh = g_ptr_array_index (sign_headers, i);

				if (ctx->header_canon_type == DKIM_CANON_SIMPLE) {
					rspamd_dkim_hash_update (ctx->headers_hash, rh->raw_value,
							rh->raw_len);
					msg_debug_dkim ("update signature with header: %*s",
							(gint)rh->raw_len, rh->raw_value);
				}
				else {
					if (!rspamd_dkim_canonize_header_relaxed (ctx, rh->value,
							header_name, FALSE)) {

						g_ptr_array_free (sign_headers, TRUE);
						return FALSE;
					}
				}
			}

			g_ptr_array_free (sign_headers, TRUE);
		}
	}
	else {
		/* For signature check just use the saved dkim header */
		if (ctx->header_canon_type == DKIM_CANON_SIMPLE) {
			/* We need to find our own signature and use it */
			rh = g_hash_table_lookup (task->raw_headers, DKIM_SIGNHEADER);

			if (rh) {
				/* We need to find our own signature */
				if (!dkim_domain) {
					return FALSE;
				}


				LL_FOREACH (rh, rh_iter) {
					if (rspamd_substring_search_twoway (rh->raw_value,
							rh->raw_len, dkim_domain,
							strlen (dkim_domain)) != -1) {
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

/**
 * Check task for dkim context using dkim key
 * @param ctx dkim verify context
 * @param key dkim key (from cache or from dns request)
 * @param task task to check
 * @return
 */
gint
rspamd_dkim_check (rspamd_dkim_context_t *ctx,
	rspamd_dkim_key_t *key,
	struct rspamd_task *task)
{
	const gchar *p, *body_end, *body_start;
	guchar raw_digest[EVP_MAX_MD_SIZE];
	gsize dlen;
	gint res = DKIM_CONTINUE;
	guint i;
	struct rspamd_dkim_header *dh;
	gint nid;

	g_return_val_if_fail (ctx != NULL,		 DKIM_ERROR);
	g_return_val_if_fail (key != NULL,		 DKIM_ERROR);
	g_return_val_if_fail (task->msg.len > 0, DKIM_ERROR);

	/* First of all find place of body */
	p = task->msg.begin;
	body_end = task->msg.begin + task->msg.len;
	body_start = task->raw_headers_content.body_start;

	if (!body_start) {
		return DKIM_RECORD_ERROR;
	}

	/* Start canonization of body part */
	if (!rspamd_dkim_canonize_body (&ctx->common, body_start, body_end)) {
		return DKIM_RECORD_ERROR;
	}
	/* Now canonize headers */
	for (i = 0; i < ctx->common.hlist->len; i++) {
		dh = g_ptr_array_index (ctx->common.hlist, i);
		rspamd_dkim_canonize_header (&ctx->common, task, dh->name, dh->count,
				NULL, NULL);
	}

	/* Canonize dkim signature */
	rspamd_dkim_canonize_header (&ctx->common, task, DKIM_SIGNHEADER, 1,
			ctx->dkim_header, ctx->domain);

	dlen = EVP_MD_CTX_size (ctx->common.body_hash);
	EVP_DigestFinal_ex (ctx->common.body_hash, raw_digest, NULL);

	/* Check bh field */
	if (memcmp (ctx->bh, raw_digest, ctx->bhlen) != 0) {
		msg_debug_dkim ("bh value mismatch: %*xs versus %*xs", dlen, ctx->bh,
				dlen, raw_digest);
		return DKIM_REJECT;
	}

	dlen = EVP_MD_CTX_size (ctx->common.headers_hash);
	EVP_DigestFinal_ex (ctx->common.headers_hash, raw_digest, NULL);
	/* Check headers signature */

	if (ctx->sig_alg == DKIM_SIGN_RSASHA1) {
		nid = NID_sha1;
	}
	else if (ctx->sig_alg == DKIM_SIGN_RSASHA256) {
		nid = NID_sha256;
	}
	else {
		/* Not reached */
		nid = NID_sha1;
	}

	if (RSA_verify (nid, raw_digest, dlen, ctx->b, ctx->blen, key->key_rsa) != 1) {
		msg_debug_dkim ("rsa verify failed");
		res = DKIM_REJECT;
	}

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
rspamd_dkim_sign_key_load (const gchar *path, GError **err)
{
	gpointer map;
	gsize len = 0;
	rspamd_dkim_sign_key_t *nkey;

	map = rspamd_file_xmap (path, PROT_READ, &len);

	if (map == NULL) {
		g_set_error (err, dkim_error_quark (), DKIM_SIGERROR_KEYFAIL,
				"cannot map private key %s: %s",
				path, strerror (errno));

		return NULL;
	}

	nkey = g_slice_alloc0 (sizeof (*nkey));
	(void)mlock (map, len);
	nkey->keydata = map;
	nkey->keylen = len;

	nkey->key_bio = BIO_new_mem_buf (map, len);

	if (!PEM_read_bio_PrivateKey (nkey->key_bio, &nkey->key_evp, NULL, NULL)) {
		g_set_error (err, dkim_error_quark (), DKIM_SIGERROR_KEYFAIL,
				"cannot read private key from %s: %s",
				path, ERR_error_string (ERR_get_error (), NULL));
		rspamd_dkim_sign_key_free (nkey);

		return NULL;
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

rspamd_dkim_sign_context_t *
rspamd_create_dkim_sign_context (struct rspamd_task *task,
		rspamd_dkim_sign_key_t *priv_key,
		gint headers_canon,
		gint body_canon,
		const gchar *headers,
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

	if (!rspamd_dkim_parse_hdrlist_common (&nctx->common, headers, strlen (headers),
			err)) {
		return NULL;
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


GString*
rspamd_dkim_sign (struct rspamd_task *task,
		const gchar *selector, const gchar *domain,
		time_t expire, gsize len,
		rspamd_dkim_sign_context_t *ctx)
{
	GString *hdr;
	struct rspamd_dkim_header *dh;
	const gchar *p, *body_end, *body_start;
	guchar raw_digest[EVP_MAX_MD_SIZE];
	gsize dlen;
	guint i, j;
	gchar *b64_data;
	guchar *rsa_buf;
	guint rsa_len;

	g_assert (ctx != NULL);

	/* First of all find place of body */
	p = task->msg.begin;
	body_end = task->msg.begin + task->msg.len;
	body_start = task->raw_headers_content.body_start;

	if (len > 0) {
		ctx->common.len = len;
	}

	if (!body_start) {
		return NULL;
	}

	/* Start canonization of body part */
	if (!rspamd_dkim_canonize_body (&ctx->common, body_start, body_end)) {
		return NULL;
	}

	hdr = g_string_sized_new (255);
	rspamd_printf_gstring (hdr, "v=1;a=rsa-sha256;c=%s/%s;d=%s;s=%s;",
			ctx->common.header_canon_type == DKIM_CANON_RELAXED ? "relaxed" : "simple",
			ctx->common.body_canon_type == DKIM_CANON_RELAXED ? "relaxed" : "simple",
			domain, selector);

	if (expire > 0) {
		rspamd_printf_gstring (hdr, "x=%t;", expire);
	}
	if (len > 0) {
		rspamd_printf_gstring (hdr, "l=%z;", len);
	}

	rspamd_printf_gstring (hdr, "t=%t;h=", time (NULL));

	/* Now canonize headers */
	for (i = 0; i < ctx->common.hlist->len; i++) {
		dh = g_ptr_array_index (ctx->common.hlist, i);

		if (g_hash_table_lookup (task->raw_headers, dh->name)) {
			rspamd_dkim_canonize_header (&ctx->common, task, dh->name, dh->count,
					NULL, NULL);

			for (j = 0; j < dh->count; j++) {
				rspamd_printf_gstring (hdr, "%s:", dh->name);
			}
		}
	}

	/* Replace the last ':' with ';' */
	hdr->str[hdr->len - 1] = ';';

	dlen = EVP_MD_CTX_size (ctx->common.body_hash);
	EVP_DigestFinal_ex (ctx->common.body_hash, raw_digest, NULL);

	b64_data = rspamd_encode_base64 (raw_digest, dlen, 0, NULL);
	rspamd_printf_gstring (hdr, "bh=%s;b=", b64_data);
	g_free (b64_data);

	if (ctx->common.header_canon_type == DKIM_CANON_RELAXED) {
		if (!rspamd_dkim_canonize_header_relaxed (&ctx->common,
				hdr->str,
				DKIM_SIGNHEADER,
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

	b64_data = rspamd_encode_base64 (rsa_buf, rsa_len, 0, NULL);
	rspamd_printf_gstring (hdr, "%s", b64_data);
	g_free (b64_data);

	return hdr;
}
