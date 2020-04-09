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
/*
 * OSB tokenizer
 */


#include "tokenizers.h"
#include "stat_internal.h"
#include "libmime/lang_detection.h"

/* Size for features pipe */
#define DEFAULT_FEATURE_WINDOW_SIZE 5
#define DEFAULT_OSB_VERSION 2

static const int primes[] = {
	1, 7,
	3, 13,
	5, 29,
	11, 51,
	23, 101,
	47, 203,
	97, 407,
	197, 817,
	397, 1637,
	797, 3277,
};

static const guchar osb_tokenizer_magic[] = {'o', 's', 'b', 't', 'o', 'k', 'v', '2'};

enum rspamd_osb_hash_type {
	RSPAMD_OSB_HASH_COMPAT = 0,
	RSPAMD_OSB_HASH_XXHASH,
	RSPAMD_OSB_HASH_SIPHASH
};

struct rspamd_osb_tokenizer_config {
	guchar magic[8];
	gshort version;
	gshort window_size;
	enum rspamd_osb_hash_type ht;
	guint64 seed;
	rspamd_sipkey_t sk;
};

/*
 * Return default config
 */
static struct rspamd_osb_tokenizer_config *
rspamd_tokenizer_osb_default_config (void)
{
	static struct rspamd_osb_tokenizer_config def;

	if (memcmp (def.magic, osb_tokenizer_magic, sizeof (osb_tokenizer_magic)) != 0) {
		memset (&def, 0, sizeof (def));
		memcpy (def.magic, osb_tokenizer_magic, sizeof (osb_tokenizer_magic));
		def.version = DEFAULT_OSB_VERSION;
		def.window_size = DEFAULT_FEATURE_WINDOW_SIZE;
		def.ht = RSPAMD_OSB_HASH_XXHASH;
		def.seed = 0xdeadbabe;
	}

	return &def;
}

static struct rspamd_osb_tokenizer_config *
rspamd_tokenizer_osb_config_from_ucl (rspamd_mempool_t * pool,
		const ucl_object_t *obj)
{
	const ucl_object_t *elt;
	struct rspamd_osb_tokenizer_config *cf, *def;
	guchar *key = NULL;
	gsize keylen;


	if (pool != NULL) {
		cf = rspamd_mempool_alloc0 (pool, sizeof (*cf));
	}
	else {
		cf = g_malloc0 (sizeof (*cf));
	}

	/* Use default config */
	def = rspamd_tokenizer_osb_default_config ();
	memcpy (cf, def, sizeof (*cf));

	elt = ucl_object_lookup (obj, "hash");
	if (elt != NULL && ucl_object_type (elt) == UCL_STRING) {
		if (g_ascii_strncasecmp (ucl_object_tostring (elt), "xxh", 3)
				== 0) {
			cf->ht = RSPAMD_OSB_HASH_XXHASH;
			elt = ucl_object_lookup (obj, "seed");
			if (elt != NULL && ucl_object_type (elt) == UCL_INT) {
				cf->seed = ucl_object_toint (elt);
			}
		}
		else if (g_ascii_strncasecmp (ucl_object_tostring (elt), "sip", 3)
				== 0) {
			cf->ht = RSPAMD_OSB_HASH_SIPHASH;
			elt = ucl_object_lookup (obj, "key");

			if (elt != NULL && ucl_object_type (elt) == UCL_STRING) {
				key = rspamd_decode_base32 (ucl_object_tostring (elt),
						0, &keylen, RSPAMD_BASE32_DEFAULT);
				if (keylen < sizeof (rspamd_sipkey_t)) {
					msg_warn ("siphash key is too short: %z", keylen);
					g_free (key);
				}
				else {
					memcpy (cf->sk, key, sizeof (cf->sk));
					g_free (key);
				}
			}
			else {
				msg_warn_pool ("siphash cannot be used without key");
			}

		}
	}
	else {
		elt = ucl_object_lookup (obj, "compat");
		if (elt != NULL && ucl_object_toboolean (elt)) {
			cf->ht = RSPAMD_OSB_HASH_COMPAT;
		}
	}

	elt = ucl_object_lookup (obj, "window");
	if (elt != NULL && ucl_object_type (elt) == UCL_INT) {
		cf->window_size = ucl_object_toint (elt);
		if (cf->window_size > DEFAULT_FEATURE_WINDOW_SIZE * 4) {
			msg_err_pool ("too large window size: %d", cf->window_size);
			cf->window_size = DEFAULT_FEATURE_WINDOW_SIZE;
		}
	}

	return cf;
}

gpointer
rspamd_tokenizer_osb_get_config (rspamd_mempool_t *pool,
		struct rspamd_tokenizer_config *cf,
		gsize *len)
{
	struct rspamd_osb_tokenizer_config *osb_cf, *def;

	if (cf != NULL && cf->opts != NULL) {
		osb_cf = rspamd_tokenizer_osb_config_from_ucl (pool, cf->opts);
	}
	else {
		def = rspamd_tokenizer_osb_default_config ();
		osb_cf = rspamd_mempool_alloc (pool, sizeof (*osb_cf));
		memcpy (osb_cf, def, sizeof (*osb_cf));
		/* Do not write sipkey to statfile */
	}

	if (osb_cf->ht == RSPAMD_OSB_HASH_SIPHASH) {
		msg_info_pool ("siphash key is not stored into statfiles, so you'd "
				"need to keep it inside the configuration");
	}

	memset (osb_cf->sk, 0, sizeof (osb_cf->sk));

	if (len != NULL) {
		*len = sizeof (*osb_cf);
	}

	return osb_cf;
}

#if 0
gboolean
rspamd_tokenizer_osb_compatible_config (struct rspamd_tokenizer_runtime *rt,
			gpointer ptr, gsize len)
{
	struct rspamd_osb_tokenizer_config *osb_cf, *test_cf;
	gboolean ret = FALSE;

	test_cf = rt->config;
	g_assert (test_cf != NULL);

	if (len == sizeof (*osb_cf)) {
		osb_cf = ptr;

		if (memcmp (osb_cf, osb_tokenizer_magic, sizeof (osb_tokenizer_magic)) != 0) {
			ret = test_cf->ht == RSPAMD_OSB_HASH_COMPAT;
		}
		else {
			if (osb_cf->version == DEFAULT_OSB_VERSION) {
				/* We can compare them directly now */
				ret = (memcmp (osb_cf, test_cf, sizeof (*osb_cf)
						- sizeof (osb_cf->sk))) == 0;
			}
		}
	}
	else {
		/* We are compatible now merely with fallback config */
		if (test_cf->ht == RSPAMD_OSB_HASH_COMPAT) {
			ret = TRUE;
		}
	}

	return ret;
}

gboolean
rspamd_tokenizer_osb_load_config (rspamd_mempool_t *pool,
		struct rspamd_tokenizer_runtime *rt,
		gpointer ptr, gsize len)
{
	struct rspamd_osb_tokenizer_config *osb_cf;

	if (ptr == NULL || len == 0) {
		osb_cf = rspamd_tokenizer_osb_config_from_ucl (pool, rt->tkcf->opts);

		if (osb_cf->ht != RSPAMD_OSB_HASH_COMPAT) {
			/* Trying to load incompatible configuration */
			msg_err_pool ("cannot load tokenizer configuration from a legacy "
					"statfile; maybe you have forgotten to set 'compat' option"
					" in the tokenizer configuration");

			return FALSE;
		}
	}
	else {
		g_assert (len == sizeof (*osb_cf));
		osb_cf = ptr;
	}

	rt->config = osb_cf;
	rt->conf_len = sizeof (*osb_cf);

	return TRUE;
}

gboolean
rspamd_tokenizer_osb_is_compat (struct rspamd_tokenizer_runtime *rt)
{
	struct rspamd_osb_tokenizer_config *osb_cf = rt->config;

	return (osb_cf->ht == RSPAMD_OSB_HASH_COMPAT);
}
#endif

struct token_pipe_entry {
	guint64 h;
	rspamd_stat_token_t *t;
};

gint
rspamd_tokenizer_osb (struct rspamd_stat_ctx *ctx,
					  struct rspamd_task *task,
					  GArray *words,
					  gboolean is_utf,
					  const gchar *prefix,
					  GPtrArray *result)
{
	rspamd_token_t *new_tok = NULL;
	rspamd_stat_token_t *token;
	struct rspamd_osb_tokenizer_config *osb_cf;
	guint64 cur, seed;
	struct token_pipe_entry *hashpipe;
	guint32 h1, h2;
	gsize token_size;
	guint processed = 0, i, w, window_size, token_flags = 0;

	if (words == NULL) {
		return FALSE;
	}

	osb_cf = ctx->tkcf;
	window_size = osb_cf->window_size;

	if (prefix) {
		seed = rspamd_cryptobox_fast_hash_specific (RSPAMD_CRYPTOBOX_XXHASH64,
				prefix, strlen (prefix), osb_cf->seed);
	}
	else {
		seed = osb_cf->seed;
	}

	hashpipe = g_alloca (window_size * sizeof (hashpipe[0]));
	for (i = 0; i < window_size; i++) {
		hashpipe[i].h = 0xfe;
		hashpipe[i].t = NULL;
	}

	token_size = sizeof (rspamd_token_t) +
			sizeof (gdouble) * ctx->statfiles->len;
	g_assert (token_size > 0);

	for (w = 0; w < words->len; w ++) {
		token = &g_array_index (words, rspamd_stat_token_t, w);
		token_flags = token->flags;
		const gchar *begin;
		gsize len;

		if (token->flags &
			(RSPAMD_STAT_TOKEN_FLAG_STOP_WORD|RSPAMD_STAT_TOKEN_FLAG_SKIPPED)) {
			/* Skip stop/skipped words */
			continue;
		}

		if (token->flags & RSPAMD_STAT_TOKEN_FLAG_TEXT) {
			begin = token->stemmed.begin;
			len = token->stemmed.len;
		}
		else {
			begin = token->original.begin;
			len = token->original.len;
		}

		if (osb_cf->ht == RSPAMD_OSB_HASH_COMPAT) {
			rspamd_ftok_t ftok;

			ftok.begin = begin;
			ftok.len = len;
			cur = rspamd_fstrhash_lc (&ftok, is_utf);
		}
		else {
			/* We know that the words are normalized */
			if (osb_cf->ht == RSPAMD_OSB_HASH_XXHASH) {
				cur = rspamd_cryptobox_fast_hash_specific (RSPAMD_CRYPTOBOX_XXHASH64,
						begin, len, osb_cf->seed);
			}
			else {
				rspamd_cryptobox_siphash ((guchar *)&cur, begin,
						len, osb_cf->sk);

				if (prefix) {
					cur ^= seed;
				}
			}
		}

		if (token_flags & RSPAMD_STAT_TOKEN_FLAG_UNIGRAM) {
			new_tok = rspamd_mempool_alloc0 (task->task_pool, token_size);
			new_tok->flags = token_flags;
			new_tok->t1 = token;
			new_tok->t2 = token;
			new_tok->data = cur;
			new_tok->window_idx = 0;
			g_ptr_array_add (result, new_tok);

			continue;
		}

#define ADD_TOKEN do {\
    new_tok = rspamd_mempool_alloc0 (task->task_pool, token_size); \
    new_tok->flags = token_flags; \
    new_tok->t1 = hashpipe[0].t; \
    new_tok->t2 = hashpipe[i].t; \
    if (osb_cf->ht == RSPAMD_OSB_HASH_COMPAT) { \
        h1 = ((guint32)hashpipe[0].h) * primes[0] + \
            ((guint32)hashpipe[i].h) * primes[i << 1]; \
        h2 = ((guint32)hashpipe[0].h) * primes[1] + \
            ((guint32)hashpipe[i].h) * primes[(i << 1) - 1]; \
        memcpy((guchar *)&new_tok->data, &h1, sizeof (h1)); \
        memcpy(((guchar *)&new_tok->data) + sizeof (h1), &h2, sizeof (h2)); \
    } \
    else { \
        new_tok->data = hashpipe[0].h * primes[0] + hashpipe[i].h * primes[i << 1]; \
    } \
    new_tok->window_idx = i; \
    g_ptr_array_add (result, new_tok); \
  } while(0)

		if (processed < window_size) {
			/* Just fill a hashpipe */
			++processed;
			hashpipe[window_size - processed].h = cur;
			hashpipe[window_size - processed].t = token;
		}
		else {
			/* Shift hashpipe */
			for (i = window_size - 1; i > 0; i--) {
				hashpipe[i] = hashpipe[i - 1];
			}
			hashpipe[0].h = cur;
			hashpipe[0].t = token;

			processed++;

			for (i = 1; i < window_size; i++) {
				if (!(hashpipe[i].t->flags & RSPAMD_STAT_TOKEN_FLAG_EXCEPTION)) {
					ADD_TOKEN;
				}
			}
		}
	}

	if (processed > 1 && processed <= window_size) {
		processed --;
		memmove (hashpipe, &hashpipe[window_size - processed],
				processed * sizeof (hashpipe[0]));

		for (i = 1; i < processed; i++) {
			ADD_TOKEN;
		}
	}

#undef ADD_TOKEN

	return TRUE;
}
