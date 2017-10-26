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
#include "fstring.h"
#include "ottery.h"
#include "cryptobox.h"
#include "unix-std.h"

static const int mapping_size = 64 * 8192 + 1;
static const int max_seg = 32;
static const int random_fuzz_cnt = 10000;
enum rspamd_cryptobox_mode mode = RSPAMD_CRYPTOBOX_MODE_25519;

static void *
create_mapping (int mapping_len, guchar **beg, guchar **end)
{
	void *map;
	int psize = getpagesize ();

	map = mmap (NULL, mapping_len + psize * 3, PROT_READ|PROT_WRITE,
			MAP_ANON|MAP_SHARED, -1, 0);
	g_assert (map != 0);
	memset (map, 0, mapping_len + psize * 3);
	mprotect (map, psize, PROT_NONE);
	/* Misalign pointer */
	*beg = ((guchar *)map) + psize + 1;
	*end = *beg + mapping_len;
	mprotect (*beg + mapping_len - 1 + psize, psize, PROT_NONE);

	return map;
}

static void
check_result (const rspamd_nm_t key, const rspamd_nonce_t nonce,
		const rspamd_mac_t mac, guchar *begin, guchar *end)
{
	guint64 *t = (guint64 *)begin;

	g_assert (rspamd_cryptobox_decrypt_nm_inplace (begin, end - begin, nonce, key,
			mac, mode));

	while (t < (guint64 *)end) {
		g_assert (*t == 0);
		t ++;
	}
}

static int
create_random_split (struct rspamd_cryptobox_segment *seg, int mseg,
		guchar *begin, guchar *end)
{
	gsize remain = end - begin;
	gint used = 0;

	while (remain > 0 && used < mseg - 1) {
		seg->data = begin;
		seg->len = ottery_rand_range (remain - 1) + 1;

		begin += seg->len;
		remain -= seg->len;
		used ++;
		seg ++;
	}

	if (remain > 0) {
		seg->data = begin;
		seg->len = remain;
		used ++;
	}

	return used;
}

static int
create_realistic_split (struct rspamd_cryptobox_segment *seg, int mseg,
		guchar *begin, guchar *end)
{
	gsize remain = end - begin;
	gint used = 0;
	static const int small_seg = 512, medium_seg = 2048;

	while (remain > 0 && used < mseg - 1) {
		seg->data = begin;

		if (ottery_rand_uint32 () % 2 == 0) {
			seg->len = ottery_rand_range (small_seg) + 1;
		}
		else {
			seg->len = ottery_rand_range (medium_seg) +
					small_seg;
		}
		if (seg->len > remain) {
			seg->len = remain;
		}

		begin += seg->len;
		remain -= seg->len;
		used ++;
		seg ++;
	}

	if (remain > 0) {
		seg->data = begin;
		seg->len = remain;
		used ++;
	}

	return used;
}

static int
create_constrainted_split (struct rspamd_cryptobox_segment *seg, int mseg,
		int constraint,
		guchar *begin, guchar *end)
{
	gsize remain = end - begin;
	gint used = 0;

	while (remain > 0 && used < mseg - 1) {
		seg->data = begin;
		seg->len = constraint;
		if (seg->len > remain) {
			seg->len = remain;
		}
		begin += seg->len;
		remain -= seg->len;
		used ++;
		seg ++;
	}

	if (remain > 0) {
		seg->data = begin;
		seg->len = remain;
		used ++;
	}

	return used;
}

void
rspamd_cryptobox_test_func (void)
{
	void *map;
	guchar *begin, *end;
	rspamd_nm_t key;
	rspamd_nonce_t nonce;
	rspamd_mac_t mac;
	struct rspamd_cryptobox_segment *seg;
	double t1, t2;
	gint i, cnt, ms;
	gboolean checked_openssl = FALSE;

	map = create_mapping (mapping_size, &begin, &end);

	ottery_rand_bytes (key, sizeof (key));
	ottery_rand_bytes (nonce, sizeof (nonce));

	memset (mac, 0, sizeof (mac));
	seg = g_slice_alloc0 (sizeof (*seg) * max_seg * 10);

	/* Test baseline */
	t1 = rspamd_get_ticks (TRUE);
	rspamd_cryptobox_encrypt_nm_inplace (begin, end - begin, nonce, key, mac,
			mode);
	t2 = rspamd_get_ticks (TRUE);
	check_result (key, nonce, mac, begin, end);

	msg_info ("baseline encryption: %.0f", t2 - t1);

	mode = RSPAMD_CRYPTOBOX_MODE_NIST;
	t1 = rspamd_get_ticks (TRUE);
	rspamd_cryptobox_encrypt_nm_inplace (begin,
			end - begin,
			nonce,
			key,
			mac,
			mode);
	t2 = rspamd_get_ticks (TRUE);
	check_result (key, nonce, mac, begin, end);

	msg_info ("openssl baseline encryption: %.0f", t2 - t1);
	mode = RSPAMD_CRYPTOBOX_MODE_25519;

start:
	/* A single chunk as vector */
	seg[0].data = begin;
	seg[0].len = end - begin;
	t1 = rspamd_get_ticks (TRUE);
	rspamd_cryptobox_encryptv_nm_inplace (seg, 1, nonce, key, mac, mode);
	t2 = rspamd_get_ticks (TRUE);

	check_result (key, nonce, mac, begin, end);

	msg_info ("bulk encryption: %.0f", t2 - t1);

	/* Two chunks as vector */
	seg[0].data = begin;
	seg[0].len = (end - begin) / 2;
	seg[1].data = begin + seg[0].len;
	seg[1].len = (end - begin) - seg[0].len;
	t1 = rspamd_get_ticks (TRUE);
	rspamd_cryptobox_encryptv_nm_inplace (seg, 2, nonce, key, mac, mode);
	t2 = rspamd_get_ticks (TRUE);

	check_result (key, nonce, mac, begin, end);

	msg_info ("2 equal chunks encryption: %.0f", t2 - t1);

	seg[0].data = begin;
	seg[0].len = 1;
	seg[1].data = begin + seg[0].len;
	seg[1].len = (end - begin) - seg[0].len;
	t1 = rspamd_get_ticks (TRUE);
	rspamd_cryptobox_encryptv_nm_inplace (seg, 2, nonce, key, mac, mode);
	t2 = rspamd_get_ticks (TRUE);

	check_result (key, nonce, mac, begin, end);

	msg_info ("small and large chunks encryption: %.0f", t2 - t1);

	seg[0].data = begin;
	seg[0].len = (end - begin) - 3;
	seg[1].data = begin + seg[0].len;
	seg[1].len = (end - begin) - seg[0].len;
	t1 = rspamd_get_ticks (TRUE);
	rspamd_cryptobox_encryptv_nm_inplace (seg, 2, nonce, key, mac, mode);
	t2 = rspamd_get_ticks (TRUE);

	check_result (key, nonce, mac, begin, end);

	msg_info ("large and small chunks encryption: %.0f", t2 - t1);

	/* Random two chunks as vector */
	seg[0].data = begin;
	seg[0].len = ottery_rand_range (end - begin - 1) + 1;
	seg[1].data = begin + seg[0].len;
	seg[1].len = (end - begin) - seg[0].len;
	t1 = rspamd_get_ticks (TRUE);
	rspamd_cryptobox_encryptv_nm_inplace (seg, 2, nonce, key, mac, mode);
	t2 = rspamd_get_ticks (TRUE);

	check_result (key, nonce, mac, begin, end);

	msg_info ("random 2 chunks encryption: %.0f", t2 - t1);

	/* 3 specific chunks */
	seg[0].data = begin;
	seg[0].len = 2;
	seg[1].data = begin + seg[0].len;
	seg[1].len = 2049;
	seg[2].data = begin + seg[0].len + seg[1].len;
	seg[2].len = (end - begin) - seg[0].len - seg[1].len;
	t1 = rspamd_get_ticks (TRUE);
	rspamd_cryptobox_encryptv_nm_inplace (seg, 3, nonce, key, mac, mode);
	t2 = rspamd_get_ticks (TRUE);

	check_result (key, nonce, mac, begin, end);

	msg_info ("small, medium and large chunks encryption: %.0f", t2 - t1);

	cnt = create_random_split (seg, max_seg, begin, end);
	t1 = rspamd_get_ticks (TRUE);
	rspamd_cryptobox_encryptv_nm_inplace (seg, cnt, nonce, key, mac, mode);
	t2 = rspamd_get_ticks (TRUE);

	check_result (key, nonce, mac, begin, end);

	msg_info ("random split of %d chunks encryption: %.0f", cnt, t2 - t1);

	cnt = create_realistic_split (seg, max_seg, begin, end);
	t1 = rspamd_get_ticks (TRUE);
	rspamd_cryptobox_encryptv_nm_inplace (seg, cnt, nonce, key, mac, mode);
	t2 = rspamd_get_ticks (TRUE);

	check_result (key, nonce, mac, begin, end);

	msg_info ("realistic split of %d chunks encryption: %.0f", cnt, t2 - t1);

	cnt = create_constrainted_split (seg, max_seg + 1, 32, begin, end);
	t1 = rspamd_get_ticks (TRUE);
	rspamd_cryptobox_encryptv_nm_inplace (seg, cnt, nonce, key, mac, mode);
	t2 = rspamd_get_ticks (TRUE);

	check_result (key, nonce, mac, begin, end);

	msg_info ("constrainted split of %d chunks encryption: %.0f", cnt, t2 - t1);

	for (i = 0; i < random_fuzz_cnt; i ++) {
		ms = ottery_rand_range (i % max_seg * 2) + 1;
		cnt = create_random_split (seg, ms, begin, end);
		t1 = rspamd_get_ticks (TRUE);
		rspamd_cryptobox_encryptv_nm_inplace (seg, cnt, nonce, key, mac, mode);
		t2 = rspamd_get_ticks (TRUE);

		check_result (key, nonce, mac, begin, end);

		if (i % 1000 == 0) {
			msg_info ("random fuzz iterations: %d", i);
		}
	}
	for (i = 0; i < random_fuzz_cnt; i ++) {
		ms = ottery_rand_range (i % max_seg * 2) + 1;
		cnt = create_realistic_split (seg, ms, begin, end);
		t1 = rspamd_get_ticks (TRUE);
		rspamd_cryptobox_encryptv_nm_inplace (seg, cnt, nonce, key, mac, mode);
		t2 = rspamd_get_ticks (TRUE);

		check_result (key, nonce, mac, begin, end);

		if (i % 1000 == 0) {
			msg_info ("realistic fuzz iterations: %d", i);
		}
	}
	for (i = 0; i < random_fuzz_cnt; i ++) {
		ms = ottery_rand_range (i % max_seg * 10) + 1;
		cnt = create_constrainted_split (seg, ms, i, begin, end);
		t1 = rspamd_get_ticks (TRUE);
		rspamd_cryptobox_encryptv_nm_inplace (seg, cnt, nonce, key, mac, mode);
		t2 = rspamd_get_ticks (TRUE);

		check_result (key, nonce, mac, begin, end);

		if (i % 1000 == 0) {
			msg_info ("constrainted fuzz iterations: %d", i);
		}
	}

	if (!checked_openssl) {
		checked_openssl = TRUE;
		mode = RSPAMD_CRYPTOBOX_MODE_NIST;
		goto start;
	}
}
