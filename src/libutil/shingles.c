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

#define SHINGLES_WINDOW 3

struct rspamd_shingle*
rspamd_shingles_generate (GArray *input,
		const guchar key[16],
		rspamd_mempool_t *pool,
		rspamd_shingles_filter filter,
		gpointer filterd,
		enum rspamd_shingle_alg alg)
{
	struct rspamd_shingle *res;
	GArray *hashes[RSPAMD_SHINGLE_SIZE];
	rspamd_sipkey_t keys[RSPAMD_SHINGLE_SIZE];
	guchar shabuf[rspamd_cryptobox_HASHBYTES], *out_key;
	const guchar *cur_key;
	rspamd_fstring_t *row;
	rspamd_ftok_t *word;
	rspamd_cryptobox_hash_state_t bs;
	guint64 val;
	gint i, j, k, beg = 0;
	enum rspamd_cryptobox_fast_hash_type ht;

	if (pool != NULL) {
		res = rspamd_mempool_alloc (pool, sizeof (*res));
	}
	else {
		res = g_malloc (sizeof (*res));
	}

	rspamd_cryptobox_hash_init (&bs, NULL, 0);
	row = rspamd_fstring_sized_new (256);
	cur_key = key;
	out_key = (guchar *)&keys[0];

	/* Init hashes pipes and keys */
	for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
		hashes[i] = g_array_sized_new (FALSE, FALSE, sizeof (guint64),
				input->len + SHINGLES_WINDOW);
		/*
		 * To generate a set of hashes we just apply sha256 to the
		 * initial key as many times as many hashes are required and
		 * xor left and right parts of sha256 to get a single 16 bytes SIP key.
		 */
		rspamd_cryptobox_hash_update (&bs, cur_key, 16);
		rspamd_cryptobox_hash_final (&bs, shabuf);

		for (j = 0; j < 16; j ++) {
			out_key[j] = shabuf[j];
		}

		rspamd_cryptobox_hash_init (&bs, NULL, 0);
		cur_key = out_key;
		out_key += 16;
	}

	/* Now parse input words into a vector of hashes using rolling window */
	if (alg == RSPAMD_SHINGLES_OLD) {
		for (i = 0; i <= (gint)input->len; i ++) {
			if (i - beg >= SHINGLES_WINDOW || i == (gint)input->len) {
				for (j = beg; j < i; j ++) {
					word = &g_array_index (input, rspamd_ftok_t, j);
					row = rspamd_fstring_append (row, word->begin, word->len);
				}
				beg++;

				/* Now we need to create a new row here */
				for (j = 0; j < RSPAMD_SHINGLE_SIZE; j ++) {
					rspamd_cryptobox_siphash ((guchar *)&val, row->str, row->len,
							keys[j]);
					g_array_append_val (hashes[j], val);
				}

				row = rspamd_fstring_assign (row, "", 0);
			}
		}
	}
	else {
		guint64 res[SHINGLES_WINDOW * RSPAMD_SHINGLE_SIZE];
		guint64 RSPAMD_ALIGNED(32) tmpbuf[16];
		guint rlen;

		if (alg == RSPAMD_SHINGLES_XXHASH) {
			ht = RSPAMD_CRYPTOBOX_XXHASH64;
		}
		else {
			ht = RSPAMD_CRYPTOBOX_MUMHASH;
		}

		memset (res, 0, sizeof (res));

		for (i = 0; i <= (gint)input->len; i ++) {
			if (i - beg >= SHINGLES_WINDOW || i == (gint)input->len) {

				for (j = 0; j < RSPAMD_SHINGLE_SIZE; j ++) {
					/* Shift hashes window to right */
					for (k = 0; k < SHINGLES_WINDOW - 1; k ++) {
						res[j * SHINGLES_WINDOW + k] =
								res[j * SHINGLES_WINDOW + k + 1];
					}

					word = &g_array_index (input, rspamd_ftok_t, beg);
					/* Insert the last element to the pipe */
					if (word->len >= sizeof (tmpbuf)) {
						rlen = sizeof (tmpbuf);
						memcpy (tmpbuf, word->begin, rlen);
					}
					else {
						rlen = word->len / sizeof (guint64) + 1;
						memset (tmpbuf, 0, rlen * sizeof (guint64));
						memcpy (tmpbuf, word->begin, word->len);
					}

					res[j * SHINGLES_WINDOW + SHINGLES_WINDOW - 1] =
							rspamd_cryptobox_fast_hash_specific (ht,
									tmpbuf,rlen * sizeof (guint64),
									*(guint64 *)keys[j]);
					val = 0;
					for (k = 0; k < SHINGLES_WINDOW; k ++) {
						val ^= res[j * SHINGLES_WINDOW + k];
					}

					g_array_append_val (hashes[j], val);
				}
				beg++;
			}
		}
	}

	/* Now we need to filter all hashes and make a shingles result */
	for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
		res->hashes[i] = filter ((guint64 *)hashes[i]->data, hashes[i]->len,
				i, key, filterd);
		g_array_free (hashes[i], TRUE);
	}

	rspamd_fstring_free (row);

	return res;
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
