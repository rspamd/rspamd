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

void
rspamd_shingles_test_func (void)
{
	//test_case (5, 100, 0.5);
	test_case (200, 10, 0.1);
	test_case (500, 20, 0.01);
	test_case (5000, 20, 0.01);
	test_case (5000, 15, 0);
	test_case (5000, 30, 1.0);
}
