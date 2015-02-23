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
#include "siphash.h"

/* Size for features pipe */
#define DEFAULT_FEATURE_WINDOW_SIZE 5

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

int
rspamd_tokenizer_osb (struct rspamd_tokenizer_config *cf,
	rspamd_mempool_t * pool,
	GArray * input,
	GTree * tree,
	gboolean is_utf)
{
	rspamd_token_t *new = NULL;
	rspamd_fstring_t *token;
	const ucl_object_t *elt;
	guint64 *hashpipe, cur;
	guint32 h1, h2;
	guint processed = 0, i, w, window_size = DEFAULT_FEATURE_WINDOW_SIZE;
	gboolean compat = TRUE, secure = FALSE;
	gint64 seed = 0xdeadbabe;
	guchar *key = NULL;
	gsize keylen;
	struct sipkey sk;

	g_assert (tree != NULL);

	if (input == NULL) {
		return FALSE;
	}

	if (cf != NULL && cf->opts != NULL) {
		elt = ucl_object_find_key (cf->opts, "hash");
		if (elt != NULL && ucl_object_type (elt) == UCL_STRING) {
			if (g_ascii_strncasecmp (ucl_object_tostring (elt), "xxh", 3)
					== 0) {
				compat = FALSE;
				secure = FALSE;
				elt = ucl_object_find_key (cf->opts, "seed");
				if (elt != NULL && ucl_object_type (elt) == UCL_INT) {
					seed = ucl_object_toint (elt);
				}
			}
			else if (g_ascii_strncasecmp (ucl_object_tostring (elt), "sip", 3)
					== 0) {
				compat = FALSE;
				elt = ucl_object_find_key (cf->opts, "seed");

				if (elt != NULL && ucl_object_type (elt) == UCL_STRING) {
					key = rspamd_decode_base32 (ucl_object_tostring (elt),
							0, &keylen);
					if (keylen < 16) {
						msg_warn ("siphash seed is too short: %s", keylen);
						g_free (key);
					}
					else {
						secure = TRUE;
						sip_tokey (&sk, key);
						g_free (key);
					}
				}
				else {
					msg_warn ("siphash cannot be used without seed");
				}

			}
		}
		elt = ucl_object_find_key (cf->opts, "window");
		if (elt != NULL && ucl_object_type (elt) == UCL_INT) {
			window_size = ucl_object_toint (elt);
			if (window_size > DEFAULT_FEATURE_WINDOW_SIZE * 4) {
				msg_err ("too large window size: %d", window_size);
				window_size = DEFAULT_FEATURE_WINDOW_SIZE;
			}
		}
	}

	hashpipe = g_alloca (window_size * sizeof (hashpipe[0]));
	memset (hashpipe, 0xfe, window_size * sizeof (hashpipe[0]));

	for (w = 0; w < input->len; w ++) {
		token = &g_array_index (input, rspamd_fstring_t, w);

		if (compat) {
			cur = rspamd_fstrhash_lc (token, is_utf);
		}
		else {
			/* We know that the words are normalized */
			if (!secure) {
				cur = XXH64 (token->begin, token->len, seed);
			}
			else {
				cur = siphash24 (token->begin, token->len, &sk);
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

				if (compat) {
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

			if (compat) {
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
