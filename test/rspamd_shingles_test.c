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

static const gchar *
algorithm_to_string (enum rspamd_shingle_alg alg)
{
	const gchar *ret = "unknown";

	switch (alg) {
	case RSPAMD_SHINGLES_OLD:
		ret = "siphash";
		break;
	case RSPAMD_SHINGLES_XXHASH:
		ret = "xxhash";
		break;
	case RSPAMD_SHINGLES_MUMHASH:
		ret = "mumhash";
		break;
	case RSPAMD_SHINGLES_FAST:
		ret = "fasthash";
		break;
	}

	return ret;
}

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
		/* wlen = max_len; */

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
test_case (gsize cnt, gsize max_len, gdouble perm_factor,
		enum rspamd_shingle_alg alg)
{
	GArray *input;
	struct rspamd_shingle *sgl, *sgl_permuted;
	gdouble res;
	guchar key[16];
	gdouble ts1, ts2;

	ottery_rand_bytes (key, sizeof (key));
	input = generate_fuzzy_words (cnt, max_len);
	ts1 = rspamd_get_virtual_ticks ();
	sgl = rspamd_shingles_from_text (input, key, NULL,
			rspamd_shingles_default_filter, NULL, alg);
	ts2 = rspamd_get_virtual_ticks ();
	permute_vector (input, perm_factor);
	sgl_permuted = rspamd_shingles_from_text (input, key, NULL,
			rspamd_shingles_default_filter, NULL, alg);

	res = rspamd_shingles_compare (sgl, sgl_permuted);

	msg_info ("%s (%z words of %z max len, %.2f perm factor):"
			" percentage of common shingles: %.3f, generate time: %.4f sec",
			algorithm_to_string (alg), cnt, max_len, perm_factor, res, ts2 - ts1);
	//g_assert_cmpfloat (fabs ((1.0 - res) - sqrt (perm_factor)), <=, 0.25);

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

static const guint64 expected_xxhash[RSPAMD_SHINGLE_SIZE] = {
	0x33b134be11a705a, 0x36e2ea657aa36903, 0x6547b57f7470ce9d, 0x8253eb6d2f8f158e,
	0x1cc99e3cf22388f, 0x2396da27ea36ffe8, 0x1b457d208ad3d96c, 0x2d6ac733d7a2c107,
	0x17849cbed75cc4d1, 0x4dd94e772330e804, 0x39f592fa32014ed4, 0xa2f6229ad356461,
	0x6dc825879a057b37, 0x886b12cef4338b05, 0x8b23af68c186518a, 0x16932b40339aaf02,
	0x412090c6bb0b719c, 0x4d4a88cbdf1935f3, 0x233bcbddb5f67a7, 0x474719442a33dcca,
	0x2da7ec30563e622, 0x7ab90086960e1ad2, 0x3ea2b45582539f75, 0x108cd9287d95a6c5,
	0x69ba7c67c115597, 0x10880860eb75e982, 0x16f3d90e6ab995a6, 0x5f24ea09379b9f5c,
	0x3c2dc04088e8fe54, 0x340b8cf1c6f1227, 0x193bc348ed2e9ce7, 0x68454ef43da9c748,
};

static const guint64 expected_mumhash[RSPAMD_SHINGLE_SIZE] = {
	0x38d35473b80a7fc3, 0x1300531adc2d16a1, 0x26883bc89f78f4bd, 0x57de365ef6d1a62,
	0x773603185fcbb20a, 0x39c6cbd7ebbeaa88, 0x676c7445ad167e70, 0x432315d1ecc4c0b1,
	0x1380b95756dbb078, 0x9ee12832fa53b90e, 0x72970be210f0dd0b, 0x62909bd520f5956,
	0x66196965a45eb32a, 0x2466a9ca5436620e, 0x157b828b10e10f6e, 0x429bb673a523a7e5,
	0x51a6ace94f320f88, 0x23f53a30bd7d7147, 0xbee557664d3bc34c, 0x65730c88cd212a9,
	0x87e72c0cd05fd0e, 0x417a744669baeb3d, 0x78e26f7917829324, 0x439777dcfc25fdf4,
	0x582eac6ff013f00b, 0x1e40aa90e367f4af, 0x301d14a28d6c23a2, 0x34140ecb21b6c69,
	0x390a091c8b4c31b9, 0x2e35fecf9fff0ae7, 0x94322e1a5cf31f1b, 0x33cb9190905e049a,
};

static const guint64 expected_fasthash[RSPAMD_SHINGLE_SIZE] = {
	0x3843a716f94828a6, 0x13fd5386dda3b28d, 0x71cb09de527c40a, 0x5d6f59ffd839c62,
	0x7ce3633acd568476, 0x9014298cbd00167, 0x6708ec29eedb5350, 0x2882931ff2c5c410,
	0x1839d8b947b12571, 0x58f7bc3829173302, 0x4dac8103da51abc4, 0x6c5cbcc6fb1de28,
	0x31fefcef9bafb755, 0x6f2d1a0b1feca401, 0x3e71f3718e520b06, 0x42f6ba11164ab231,
	0x21164d010bd76f4a, 0x4c597ccc7b60f620, 0x2cf1ca3383b77574, 0x54ff9c01660b8add,
	0x2ca344758f40380d, 0x1b962321bd37d0f2, 0x9323bb99c32bc418, 0x375659d0eef2b8f2,
	0x1dbd23a1030084b7, 0x83cb978dee06aa0a, 0x42c97be5b27a7763, 0x3b6d6b7270ed765,
	0x125c12fdba584aed, 0x1c826397afe58763, 0x8bdbe2d43f3eda96, 0x954cda70edf6591f,
};

void
rspamd_shingles_test_func (void)
{
	enum rspamd_shingle_alg alg = RSPAMD_SHINGLES_OLD;
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

	sgl = rspamd_shingles_from_text (input, key, NULL,
				rspamd_shingles_default_filter, NULL, RSPAMD_SHINGLES_OLD);
	for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
		g_assert (sgl->hashes[i] == expected_old[i]);
	}
	g_free (sgl);

	sgl = rspamd_shingles_from_text (input, key, NULL,
			rspamd_shingles_default_filter, NULL, RSPAMD_SHINGLES_XXHASH);
	for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
		g_assert (sgl->hashes[i] == expected_xxhash[i]);
	}
	g_free (sgl);

	sgl = rspamd_shingles_from_text (input, key, NULL,
			rspamd_shingles_default_filter, NULL, RSPAMD_SHINGLES_MUMHASH);
	for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
		g_assert (sgl->hashes[i] == expected_mumhash[i]);
	}
	g_free (sgl);

	sgl = rspamd_shingles_from_text (input, key, NULL,
			rspamd_shingles_default_filter, NULL, RSPAMD_SHINGLES_FAST);
	for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
		g_assert (sgl->hashes[i] == expected_fasthash[i]);
	}
	g_free (sgl);

	for (alg = RSPAMD_SHINGLES_OLD; alg <= RSPAMD_SHINGLES_FAST; alg ++) {
		test_case (200, 10, 0.1, alg);
		test_case (500, 20, 0.01, alg);
		test_case (5000, 20, 0.01, alg);
		test_case (5000, 15, 0, alg);
		test_case (5000, 30, 1.0, alg);
		test_case (50000, 30, 0.02, alg);
		test_case (50000, 5, 0.02, alg);
		test_case (50000, 16, 0.02, alg);
	}
}
