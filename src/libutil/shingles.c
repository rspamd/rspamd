/* Copyright (c) 2014, Vsevolod Stakhov
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

#include "shingles.h"
#include "fstring.h"
#include "cryptobox.h"
#include "blake2.h"

#define SHINGLES_WINDOW 3

struct rspamd_shingle*
rspamd_shingles_generate (GArray *input,
		const guchar key[16],
		rspamd_mempool_t *pool,
		rspamd_shingles_filter filter,
		gpointer filterd)
{
	struct rspamd_shingle *res;
	GArray *hashes[RSPAMD_SHINGLE_SIZE];
	rspamd_sipkey_t keys[RSPAMD_SHINGLE_SIZE];
	guchar shabuf[BLAKE2B_OUTBYTES], *out_key;
	const guchar *cur_key;
	GString *row;
	rspamd_fstring_t *word;
	blake2b_state bs;
	guint64 val;
	gint i, j, beg = 0;
	guint8 shalen;

	if (pool != NULL) {
		res = rspamd_mempool_alloc (pool, sizeof (*res));
	}
	else {
		res = g_malloc (sizeof (*res));
	}

	blake2b_init (&bs, BLAKE2B_OUTBYTES);
	row = g_string_sized_new (256);
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
		shalen = sizeof (shabuf);
		blake2b_update (&bs, cur_key, 16);
		blake2b_final (&bs, shabuf, shalen);

		for (j = 0; j < 16; j ++) {
			out_key[j] = shabuf[j];
		}
		blake2b_init (&bs, BLAKE2B_OUTBYTES);
		cur_key = out_key;
		out_key += 16;
	}

	/* Now parse input words into a vector of hashes using rolling window */
	for (i = 0; i <= (gint)input->len; i ++) {
		if (i - beg >= SHINGLES_WINDOW || i == (gint)input->len) {
			for (j = beg; j < i; j ++) {
				word = &g_array_index (input, rspamd_fstring_t, j);
				g_string_append_len (row, word->begin, word->len);
			}
			beg++;

			/* Now we need to create a new row here */
			for (j = 0; j < RSPAMD_SHINGLE_SIZE; j ++) {
				rspamd_cryptobox_siphash ((guchar *)&val, row->str, row->len,
						keys[j]);
				g_array_append_val (hashes[j], val);
			}
			g_string_assign (row, "");
		}
	}

	/* Now we need to filter all hashes and make a shingles result */
	for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
		res->hashes[i] = filter ((guint64 *)hashes[i]->data, hashes[i]->len,
				i, key, filterd);
		g_array_free (hashes[i], TRUE);
	}

	g_string_free (row, TRUE);

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
