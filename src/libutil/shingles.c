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
#include "shingles.h"
#include "fstring.h"
#include "cryptobox.h"
#include "images.h"
#include "libstat/stat_api.h"

#define SHINGLES_WINDOW 3
#define SHINGLES_KEY_SIZE rspamd_cryptobox_SIPKEYBYTES

static guint
rspamd_shingles_keys_hash (gconstpointer k)
{
	return rspamd_cryptobox_fast_hash (k, SHINGLES_KEY_SIZE,
			rspamd_hash_seed ());
}

static gboolean
rspamd_shingles_keys_equal (gconstpointer k1, gconstpointer k2)
{
	return (memcmp (k1, k2, SHINGLES_KEY_SIZE) == 0);
}

static void
rspamd_shingles_keys_free (gpointer p)
{
	guchar **k = p;
	guint i;

	for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
		g_free (k[i]);
	}

	g_free (k);
}

static guchar **
rspamd_shingles_keys_new (void)
{
	guchar **k;
	guint i;

	k = g_malloc0 (sizeof (guchar *) * RSPAMD_SHINGLE_SIZE);

	for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
		k[i] = g_malloc0 (sizeof (guchar) * SHINGLES_KEY_SIZE);
	}

	return k;
}

static guchar **
rspamd_shingles_get_keys_cached (const guchar key[SHINGLES_KEY_SIZE])
{
	static GHashTable *ht = NULL;
	guchar **keys = NULL, *key_cpy;
	rspamd_cryptobox_hash_state_t bs;
	const guchar *cur_key;
	guchar shabuf[rspamd_cryptobox_HASHBYTES], *out_key;
	guint i;

	if (ht == NULL) {
		ht = g_hash_table_new_full (rspamd_shingles_keys_hash,
				rspamd_shingles_keys_equal, g_free, rspamd_shingles_keys_free);
	}
	else {
		keys = g_hash_table_lookup (ht, key);
	}

	if (keys == NULL) {
		keys = rspamd_shingles_keys_new ();
		key_cpy = g_malloc (SHINGLES_KEY_SIZE);
		memcpy (key_cpy, key, SHINGLES_KEY_SIZE);

		/* Generate keys */
		rspamd_cryptobox_hash_init (&bs, NULL, 0);
		cur_key = key;

		for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
			/*
			 * To generate a set of hashes we just apply sha256 to the
			 * initial key as many times as many hashes are required and
			 * xor left and right parts of sha256 to get a single 16 bytes SIP key.
			 */
			out_key = keys[i];
			rspamd_cryptobox_hash_update (&bs, cur_key, 16);
			rspamd_cryptobox_hash_final (&bs, shabuf);

			memcpy (out_key, shabuf, 16);
			rspamd_cryptobox_hash_init (&bs, NULL, 0);
			cur_key = out_key;
		}

		g_hash_table_insert (ht, key_cpy, keys);
	}

	return keys;
}

struct rspamd_shingle* RSPAMD_OPTIMIZE("unroll-loops")
rspamd_shingles_from_text (GArray *input,
		const guchar key[16],
		rspamd_mempool_t *pool,
		rspamd_shingles_filter filter,
		gpointer filterd,
		enum rspamd_shingle_alg alg)
{
	struct rspamd_shingle *res;
	guint64 **hashes;
	guchar **keys;
	rspamd_fstring_t *row;
	rspamd_stat_token_t *word;
	guint64 val;
	gint i, j, k;
	gsize hlen, ilen = 0, beg = 0, widx = 0;
	enum rspamd_cryptobox_fast_hash_type ht;

	if (pool != NULL) {
		res = rspamd_mempool_alloc (pool, sizeof (*res));
	}
	else {
		res = g_malloc (sizeof (*res));
	}

	row = rspamd_fstring_sized_new (256);

	for (i = 0; i < input->len; i ++) {
		word = &g_array_index (input, rspamd_stat_token_t, i);

		if (!((word->flags & RSPAMD_STAT_TOKEN_FLAG_SKIPPED)
			|| word->stemmed.len == 0)) {
			ilen ++;
		}
	}

	/* Init hashes pipes and keys */
	hashes = g_malloc (sizeof (*hashes) * RSPAMD_SHINGLE_SIZE);
	hlen = ilen > SHINGLES_WINDOW ?
			(ilen - SHINGLES_WINDOW + 1) : 1;
	keys = rspamd_shingles_get_keys_cached (key);

	for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
		hashes[i] = g_malloc (hlen * sizeof (guint64));
	}

	/* Now parse input words into a vector of hashes using rolling window */
	if (alg == RSPAMD_SHINGLES_OLD) {
		for (i = 0; i <= (gint)ilen; i ++) {
			if (i - beg >= SHINGLES_WINDOW || i == (gint)ilen) {
				for (j = beg; j < i; j ++) {

					word = NULL;
					while (widx < input->len) {
						word = &g_array_index (input, rspamd_stat_token_t, widx);

						if ((word->flags & RSPAMD_STAT_TOKEN_FLAG_SKIPPED)
							|| word->stemmed.len == 0) {
							widx++;
						}
						else {
							break;
						}
					}

					if (word == NULL) {
						/* Nothing but exceptions */
						for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
							g_free (hashes[i]);
						}

						g_free (hashes);

						if (pool == NULL) {
							g_free (res);
						}

						rspamd_fstring_free (row);

						return NULL;
					}

					row = rspamd_fstring_append (row, word->stemmed.begin,
							word->stemmed.len);
				}

				/* Now we need to create a new row here */
				for (j = 0; j < RSPAMD_SHINGLE_SIZE; j ++) {
					rspamd_cryptobox_siphash ((guchar *)&val, row->str, row->len,
							keys[j]);
					g_assert (hlen > beg);
					hashes[j][beg] = val;
				}

				beg++;
				widx ++;

				row = rspamd_fstring_assign (row, "", 0);
			}
		}
	}
	else {
		guint64 window[SHINGLES_WINDOW * RSPAMD_SHINGLE_SIZE], seed;

		switch (alg) {
		case RSPAMD_SHINGLES_XXHASH:
			ht = RSPAMD_CRYPTOBOX_XXHASH64;
			break;
		case RSPAMD_SHINGLES_MUMHASH:
			ht = RSPAMD_CRYPTOBOX_MUMHASH;
			break;
		default:
			ht = RSPAMD_CRYPTOBOX_HASHFAST_INDEPENDENT;
			break;
		}

		memset (window, 0, sizeof (window));
		for (i = 0; i <= ilen; i ++) {
			if (i - beg >= SHINGLES_WINDOW || i == ilen) {

				for (j = 0; j < RSPAMD_SHINGLE_SIZE; j ++) {
					/* Shift hashes window to right */
					for (k = 0; k < SHINGLES_WINDOW - 1; k ++) {
						window[j * SHINGLES_WINDOW + k] =
								window[j * SHINGLES_WINDOW + k + 1];
					}

					word = NULL;

					while (widx < input->len) {
						word = &g_array_index (input, rspamd_stat_token_t, widx);

						if ((word->flags & RSPAMD_STAT_TOKEN_FLAG_SKIPPED)
							 || word->stemmed.len == 0) {
							widx++;
						}
						else {
							break;
						}
					}

					if (word == NULL) {
						/* Nothing but exceptions */
						for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
							g_free (hashes[i]);
						}

						if (pool == NULL) {
							g_free (res);
						}

						g_free (hashes);
						rspamd_fstring_free (row);

						return NULL;
					}

					/* Insert the last element to the pipe */
					memcpy (&seed, keys[j], sizeof (seed));
					window[j * SHINGLES_WINDOW + SHINGLES_WINDOW - 1] =
							rspamd_cryptobox_fast_hash_specific (ht,
									word->stemmed.begin, word->stemmed.len,
									seed);
					val = 0;
					for (k = 0; k < SHINGLES_WINDOW; k ++) {
						val ^= window[j * SHINGLES_WINDOW + k] >>
								(8 * (SHINGLES_WINDOW - k - 1));
					}

					g_assert (hlen > beg);
					hashes[j][beg] = val;
				}

				beg ++;
				widx ++;
			}
		}
	}

	/* Now we need to filter all hashes and make a shingles result */
	for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
		res->hashes[i] = filter (hashes[i], hlen,
				i, key, filterd);
		g_free (hashes[i]);
	}

	g_free (hashes);

	rspamd_fstring_free (row);

	return res;
}

struct rspamd_shingle* RSPAMD_OPTIMIZE("unroll-loops")
rspamd_shingles_from_image (guchar *dct,
		const guchar key[16],
		rspamd_mempool_t *pool,
		rspamd_shingles_filter filter,
		gpointer filterd,
		enum rspamd_shingle_alg alg)
{
	struct rspamd_shingle *shingle;
	guint64 **hashes;
	guchar **keys;
	guint64 d;
	guint64 val;
	gint i, j;
	gsize hlen, beg = 0;
	enum rspamd_cryptobox_fast_hash_type ht;
	guint64 res[SHINGLES_WINDOW * RSPAMD_SHINGLE_SIZE], seed;

	if (pool != NULL) {
		shingle = rspamd_mempool_alloc (pool, sizeof (*shingle));
	}
	else {
		shingle = g_malloc (sizeof (*shingle));
	}

	/* Init hashes pipes and keys */
	hashes = g_malloc (sizeof (*hashes) * RSPAMD_SHINGLE_SIZE);
	hlen = RSPAMD_DCT_LEN / NBBY  + 1;
	keys = rspamd_shingles_get_keys_cached (key);

	for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
		hashes[i] = g_malloc (hlen * sizeof (guint64));
	}

	switch (alg) {
	case RSPAMD_SHINGLES_OLD:
		ht = RSPAMD_CRYPTOBOX_MUMHASH;
		break;
	case RSPAMD_SHINGLES_XXHASH:
		ht = RSPAMD_CRYPTOBOX_XXHASH64;
		break;
	case RSPAMD_SHINGLES_MUMHASH:
		ht = RSPAMD_CRYPTOBOX_MUMHASH;
		break;
	default:
		ht = RSPAMD_CRYPTOBOX_HASHFAST_INDEPENDENT;
		break;
	}

	memset (res, 0, sizeof (res));
#define INNER_CYCLE_SHINGLES(s, e) for (j = (s); j < (e); j ++) { \
	d = dct[beg]; \
	memcpy (&seed, keys[j], sizeof (seed)); \
	val = rspamd_cryptobox_fast_hash_specific (ht, \
					&d, sizeof (d), \
					seed); \
	hashes[j][beg] = val; \
}
	for (i = 0; i < RSPAMD_DCT_LEN / NBBY; i ++) {
		INNER_CYCLE_SHINGLES (0, RSPAMD_SHINGLE_SIZE / 4);
		INNER_CYCLE_SHINGLES (RSPAMD_SHINGLE_SIZE / 4, RSPAMD_SHINGLE_SIZE / 2);
		INNER_CYCLE_SHINGLES (RSPAMD_SHINGLE_SIZE / 2, 3 * RSPAMD_SHINGLE_SIZE / 4);
		INNER_CYCLE_SHINGLES (3 * RSPAMD_SHINGLE_SIZE / 4, RSPAMD_SHINGLE_SIZE);

		beg++;
	}
#undef INNER_CYCLE_SHINGLES
	/* Now we need to filter all hashes and make a shingles result */
	for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
		shingle->hashes[i] = filter (hashes[i], hlen,
				i, key, filterd);
		g_free (hashes[i]);
	}

	g_free (hashes);

	return shingle;
}

guint64
rspamd_shingles_default_filter (guint64 *input, gsize count,
		gint shno, const guchar *key, gpointer ud)
{
	guint64 minimal = G_MAXUINT64;
	gsize i;

	for (i = 0; i < count; i ++) {
		if (minimal > input[i]) {
			minimal = input[i];
		}
	}

	return minimal;
}


gdouble rspamd_shingles_compare (const struct rspamd_shingle *a,
		const struct rspamd_shingle *b)
{
	gint i, common = 0;

	for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
		if (a->hashes[i] == b->hashes[i]) {
			common ++;
		}
	}

	return (gdouble)common / (gdouble)RSPAMD_SHINGLE_SIZE;
}
