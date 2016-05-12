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
#include "shingles.h"
#include "ottery.h"
#include <math.h>

static void
generate_random_string (char *begin, size_t len)
{
	gsize i;

	for (i = 0; i < len; i ++) {
		begin[i] = ottery_rand_range ('z' - 'a') + 'a';
	}
}

static GArray *
generate_fuzzy_words (gsize cnt, gsize max_len)
{
	GArray *res;
	gsize i, wlen;
	rspamd_ftok_t w;
	char *t;

	res = g_array_sized_new (FALSE, FALSE, sizeof (rspamd_ftok_t), cnt);

	for (i = 0; i < cnt; i ++) {
		wlen = ottery_rand_range (max_len) + 1;

		w.len = wlen;
		t = g_malloc (wlen);
		generate_random_string (t, wlen);
		w.begin = t;
		g_array_append_val (res, w);
	}

	return res;
}

static void
permute_vector (GArray *in, gdouble prob)
{
	gsize i, total = 0;
	rspamd_ftok_t *w;

	for (i = 0; i < in->len; i ++) {
		if (ottery_rand_unsigned () <= G_MAXUINT * prob) {
			w = &g_array_index (in, rspamd_ftok_t, i);
			generate_random_string ((gchar *)w->begin, w->len);
			total ++;
		}
	}
	msg_debug ("generated %z permutations of %ud words", total, in->len);
}

static void
free_fuzzy_words (GArray *ar)
{
	gsize i;
	rspamd_ftok_t *w;

	for (i = 0; i < ar->len; i ++) {
		w = &g_array_index (ar, rspamd_ftok_t, i);
		g_free ((gpointer)w->begin);
	}
}

static void
test_case (gsize cnt, gsize max_len, gdouble perm_factor)
{
	GArray *input;
	struct rspamd_shingle *sgl, *sgl_permuted;
	gdouble res;
	guchar key[16];
	gdouble ts1, ts2;

	ottery_rand_bytes (key, sizeof (key));
	input = generate_fuzzy_words (cnt, max_len);
	ts1 = rspamd_get_ticks ();
	sgl = rspamd_shingles_generate (input, key, NULL,
			rspamd_shingles_default_filter, NULL);
	ts2 = rspamd_get_ticks ();
	permute_vector (input, perm_factor);
	sgl_permuted = rspamd_shingles_generate (input, key, NULL,
			rspamd_shingles_default_filter, NULL);

	res = rspamd_shingles_compare (sgl, sgl_permuted);

	msg_debug ("percentage of common shingles: %.3f, generate time: %hd usec",
			res, (gint)(ts1 - ts2) * 1000);
	g_assert_cmpfloat (fabs ((1.0 - res) - sqrt (perm_factor)), <=, 0.20);

	free_fuzzy_words (input);
	g_free (sgl);
	g_free (sgl_permuted);
}

static const guint64 expected_old[RSPAMD_SHINGLE_SIZE] = {
	0x2a97e024235cedc5, 0x46238acbcc55e9e0, 0x2378ff151af075b3, 0xde1f29a95cad109,
	0x5d3bbbdb5db5d19f, 0x4d75a0ec52af10a6, 0x215ecd6372e755b5, 0x7b52295758295350,
	0x17387d1beddc7f62, 0x26264ca879ffcada, 0x49d4a65ec0ab9914, 0xa2763e6995350cf,
	0x3f4570231449c13f, 0x3309f857a0e54ee5, 0x24e4c5b561b0fce3, 0x1f153e3b275bfd1b,
	0x4d067dbc97c3fd78, 0x9ffa2d076fa4f8bc, 0x3d8907f84b9ffc6c, 0x1cfd664c5262d256,
	0xcdd7e744b699c15, 0x5544a2bbe05124f7, 0x5a4029b5d6a06f7, 0xd5adfbdc756c0e4,
	0xa504b23d9689a67e, 0x15d945f7007de115, 0xbf676c0522a2c51d, 0x1c8d8163ad4b0f93,
	0xa2c4ba20799344d7, 0x27c6f13c02134388, 0xa1d443d31fd5a3, 0x99fbca9f8563080,
};

void
rspamd_shingles_test_func (void)
{
	struct rspamd_shingle *sgl;
	guchar key[16];
	GArray *input;
	rspamd_ftok_t tok;
	int i;

	memset (key, 0, sizeof (key));
	input = g_array_sized_new (FALSE, FALSE, sizeof (rspamd_ftok_t), 5);

	for (i = 0; i < 5; i ++) {
		gchar *b = g_alloca (8);
		memset (b, 0, 8);
		memcpy (b + 1, "test", 4);
		b[0] = 'a' + i;
		tok.begin = b;
		tok.len = 5 + ((i + 1) % 4);
		g_array_append_val (input, tok);
	}

	sgl = rspamd_shingles_generate (input, key, NULL,
				rspamd_shingles_default_filter, NULL);
	for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
		g_assert (sgl->hashes[i] == expected_old[i]);
	}
	g_free (sgl);

	//test_case (5, 100, 0.5);
	test_case (200, 10, 0.1);
	test_case (500, 20, 0.01);
	test_case (5000, 20, 0.01);
	test_case (5000, 15, 0);
	test_case (5000, 30, 1.0);
}
