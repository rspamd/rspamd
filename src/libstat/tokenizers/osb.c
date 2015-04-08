/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
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

/*
 * OSB tokenizer
 */

#include "tokenizers.h"
#include "stat_internal.h"
#include "libstemmer.h"
#include "xxhash.h"
#include "cryptobox.h"

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
		def.ht = RSPAMD_OSB_HASH_COMPAT;
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
		cf = rspamd_mempool_alloc (pool, sizeof (*cf));
	}
	else {
		cf = g_slice_alloc (sizeof (*cf));
	}

	/* Use default config */
	def = rspamd_tokenizer_osb_default_config ();
	memcpy (cf, def, sizeof (*cf));

	elt = ucl_object_find_key (obj, "hash");
	if (elt != NULL && ucl_object_type (elt) == UCL_STRING) {
		if (g_ascii_strncasecmp (ucl_object_tostring (elt), "xxh", 3)
				== 0) {
			cf->ht = RSPAMD_OSB_HASH_XXHASH;
			elt = ucl_object_find_key (obj, "seed");
			if (elt != NULL && ucl_object_type (elt) == UCL_INT) {
				cf->seed = ucl_object_toint (elt);
			}
		}
		else if (g_ascii_strncasecmp (ucl_object_tostring (elt), "sip", 3)
				== 0) {
			cf->ht = RSPAMD_OSB_HASH_SIPHASH;
			elt = ucl_object_find_key (obj, "key");

			if (elt != NULL && ucl_object_type (elt) == UCL_STRING) {
				key = rspamd_decode_base32 (ucl_object_tostring (elt),
						0, &keylen);
				if (keylen < sizeof (rspamd_sipkey_t)) {
					msg_warn ("siphash key is too short: %s", keylen);
					g_free (key);
				}
				else {
					memcpy (cf->sk, key, sizeof (cf->sk));
					g_free (key);
				}
			}
			else {
				msg_warn ("siphash cannot be used without key");
			}

		}
	}

	elt = ucl_object_find_key (obj, "window");
	if (elt != NULL && ucl_object_type (elt) == UCL_INT) {
		cf->window_size = ucl_object_toint (elt);
		if (cf->window_size > DEFAULT_FEATURE_WINDOW_SIZE * 4) {
			msg_err ("too large window size: %d", cf->window_size);
			cf->window_size = DEFAULT_FEATURE_WINDOW_SIZE;
		}
	}

	return cf;
}

gpointer
rspamd_tokenizer_osb_get_config (struct rspamd_tokenizer_config *cf,
		gsize *len)
{
	struct rspamd_osb_tokenizer_config *osb_cf, *def;

	if (cf != NULL && cf->opts != NULL) {
		osb_cf = rspamd_tokenizer_osb_config_from_ucl (NULL, cf->opts);
	}
	else {
		def = rspamd_tokenizer_osb_default_config ();
		osb_cf = g_slice_alloc (sizeof (*osb_cf));
		memcpy (osb_cf, def, sizeof (*osb_cf));
	}

	if (len != NULL) {
		*len = sizeof (*osb_cf);
	}

	return osb_cf;
}

gboolean
rspamd_tokenizer_osb_compatible_config (struct rspamd_tokenizer_config *cf,
			gpointer ptr, gsize len)
{
	struct rspamd_osb_tokenizer_config *osb_cf, *test_cf;
	gboolean ret = FALSE;

	test_cf = rspamd_tokenizer_osb_get_config (cf, NULL);

	if (len == sizeof (*osb_cf)) {
		osb_cf = ptr;

		if (memcmp (osb_cf, osb_tokenizer_magic, sizeof (osb_tokenizer_magic)) != 0) {
			ret = test_cf->ht == RSPAMD_OSB_HASH_COMPAT;
		}
		else {
			if (osb_cf->version == DEFAULT_OSB_VERSION) {
				/* We can compare them directly now */
				ret = memcmp (osb_cf, test_cf, sizeof (*osb_cf)) == 0;
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

gint
rspamd_tokenizer_osb (struct rspamd_tokenizer_config *cf,
	rspamd_mempool_t * pool,
	GArray * input,
	GTree * tree,
	gboolean is_utf)
{
	rspamd_token_t *new = NULL;
	rspamd_fstring_t *token;
	struct rspamd_osb_tokenizer_config *osb_cf;
	guint64 *hashpipe, cur;
	guint32 h1, h2;
	guint processed = 0, i, w, window_size;

	g_assert (tree != NULL);

	if (input == NULL) {
		return FALSE;
	}

	if (cf != NULL && cf->opts != NULL) {
		osb_cf = rspamd_tokenizer_osb_config_from_ucl (pool, cf->opts);
	}
	else {
		osb_cf = rspamd_tokenizer_osb_default_config ();
	}

	window_size = osb_cf->window_size;

	hashpipe = g_alloca (window_size * sizeof (hashpipe[0]));
	memset (hashpipe, 0xfe, window_size * sizeof (hashpipe[0]));

	for (w = 0; w < input->len; w ++) {
		token = &g_array_index (input, rspamd_fstring_t, w);

		if (osb_cf->ht == RSPAMD_OSB_HASH_COMPAT) {
			cur = rspamd_fstrhash_lc (token, is_utf);
		}
		else {
			/* We know that the words are normalized */
			if (osb_cf->ht == RSPAMD_OSB_HASH_XXHASH) {
				cur = XXH64 (token->begin, token->len, osb_cf->seed);
			}
			else {
				rspamd_cryptobox_siphash ((guchar *)&cur, token->begin,
						token->len, osb_cf->sk);
			}
		}

		if (processed < window_size) {
			/* Just fill a hashpipe */
			hashpipe[window_size - ++processed] = cur;
		}
		else {
			/* Shift hashpipe */
			for (i = window_size - 1; i > 0; i--) {
				hashpipe[i] = hashpipe[i - 1];
			}
			hashpipe[0] = cur;
			processed++;

			for (i = 1; i < window_size; i++) {
				new = rspamd_mempool_alloc0 (pool, sizeof (rspamd_token_t));
				new->datalen = sizeof (gint64);

				if (osb_cf->ht == RSPAMD_OSB_HASH_COMPAT) {
					h1 = ((guint32)hashpipe[0]) * primes[0] +
							((guint32)hashpipe[i]) * primes[i << 1];
					h2 = ((guint32)hashpipe[0]) * primes[1] +
							((guint32)hashpipe[i]) * primes[(i << 1) - 1];

					memcpy(new->data, &h1, sizeof (h1));
					memcpy(new->data + sizeof (h1), &h2, sizeof (h2));
				}
				else {
					cur = hashpipe[0] * primes[0] + hashpipe[i] * primes[i << 1];
					memcpy (new->data, &cur, sizeof (cur));
				}

				if (g_tree_lookup (tree, new) == NULL) {
					g_tree_insert (tree, new, new);
				}
			}
		}
	}

	if (processed <= window_size) {
		for (i = 1; i < processed; i++) {
			new = rspamd_mempool_alloc0 (pool, sizeof (rspamd_token_t));
			new->datalen = sizeof (gint64);

			if (osb_cf->ht == RSPAMD_OSB_HASH_COMPAT) {
				h1 = ((guint32)hashpipe[0]) * primes[0] +
						((guint32)hashpipe[i]) * primes[i << 1];
				h2 = ((guint32)hashpipe[0]) * primes[1] +
						((guint32)hashpipe[i]) * primes[(i << 1) - 1];
				memcpy(new->data, &h1, sizeof (h1));
				memcpy(new->data + sizeof (h1), &h2, sizeof (h2));
			}
			else {
				cur = hashpipe[0] * primes[0] + hashpipe[i] * primes[i << 1];
				memcpy (new->data, &cur, sizeof (cur));
			}

			if (g_tree_lookup (tree, new) == NULL) {
				g_tree_insert (tree, new, new);
			}
		}
	}

	return TRUE;
}

/*
 * vi:ts=4
 */
