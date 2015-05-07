/*
 * Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
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


#include "config.h"
#include "main.h"
#include "shingles.h"
#include "fstring.h"
#include "ottery.h"
#include "cryptobox.h"

static const int mapping_size = 64 * 8192 + 1;
static const int max_seg = 32;
static const int random_fuzz_cnt = 10000;

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
		const rspamd_sig_t mac, guchar *begin, guchar *end)
{
	guint64 *t = (guint64 *)begin;

	g_assert (rspamd_cryptobox_decrypt_nm_inplace (begin, end - begin, nonce, key,
			mac));

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

void
rspamd_cryptobox_test_func (void)
{
	void *map;
	guchar *begin, *end;
	rspamd_nm_t key;
	rspamd_nonce_t nonce;
	rspamd_sig_t mac;
	struct rspamd_cryptobox_segment *seg;
	double t1, t2;
	gint i, cnt, ms;

	map = create_mapping (mapping_size, &begin, &end);

	ottery_rand_bytes (key, sizeof (key));
	ottery_rand_bytes (nonce, sizeof (nonce));

	memset (mac, 0, sizeof (mac));
	seg = g_slice_alloc0 (sizeof (*seg) * max_seg);

	/* Test baseline */
	t1 = rspamd_get_ticks ();
	rspamd_cryptobox_encrypt_nm_inplace (begin, end - begin, nonce, key, mac);
	t2 = rspamd_get_ticks ();
	check_result (key, nonce, mac, begin, end);

	msg_info ("baseline encryption: %.6f", t2 - t1);
	/* A single chunk as vector */
	seg[0].data = begin;
	seg[0].len = end - begin;
	t1 = rspamd_get_ticks ();
	rspamd_cryptobox_encryptv_nm_inplace (seg, 1, nonce, key, mac);
	t2 = rspamd_get_ticks ();

	check_result (key, nonce, mac, begin, end);

	msg_info ("bulk encryption: %.6f", t2 - t1);

	/* Two chunks as vector */
	seg[0].data = begin;
	seg[0].len = (end - begin) / 2;
	seg[1].data = begin + seg[0].len;
	seg[1].len = (end - begin) - seg[0].len;
	t1 = rspamd_get_ticks ();
	rspamd_cryptobox_encryptv_nm_inplace (seg, 2, nonce, key, mac);
	t2 = rspamd_get_ticks ();

	check_result (key, nonce, mac, begin, end);

	msg_info ("2 equal chunks encryption: %.6f", t2 - t1);

	seg[0].data = begin;
	seg[0].len = 1;
	seg[1].data = begin + seg[0].len;
	seg[1].len = (end - begin) - seg[0].len;
	t1 = rspamd_get_ticks ();
	rspamd_cryptobox_encryptv_nm_inplace (seg, 2, nonce, key, mac);
	t2 = rspamd_get_ticks ();

	check_result (key, nonce, mac, begin, end);

	msg_info ("small and large chunks encryption: %.6f", t2 - t1);

	seg[0].data = begin;
	seg[0].len = (end - begin) - 3;
	seg[1].data = begin + seg[0].len;
	seg[1].len = (end - begin) - seg[0].len;
	t1 = rspamd_get_ticks ();
	rspamd_cryptobox_encryptv_nm_inplace (seg, 2, nonce, key, mac);
	t2 = rspamd_get_ticks ();

	check_result (key, nonce, mac, begin, end);

	msg_info ("large and small chunks encryption: %.6f", t2 - t1);

	/* Random two chunks as vector */
	seg[0].data = begin;
	seg[0].len = ottery_rand_range (end - begin - 1) + 1;
	seg[1].data = begin + seg[0].len;
	seg[1].len = (end - begin) - seg[0].len;
	t1 = rspamd_get_ticks ();
	rspamd_cryptobox_encryptv_nm_inplace (seg, 2, nonce, key, mac);
	t2 = rspamd_get_ticks ();

	check_result (key, nonce, mac, begin, end);

	msg_info ("random 2 chunks encryption: %.6f", t2 - t1);

	/* 3 specific chunks */
	seg[0].data = begin;
	seg[0].len = 2;
	seg[1].data = begin + seg[0].len;
	seg[1].len = 2049;
	seg[2].data = begin + seg[0].len + seg[1].len;
	seg[2].len = (end - begin) - seg[0].len - seg[1].len;
	t1 = rspamd_get_ticks ();
	rspamd_cryptobox_encryptv_nm_inplace (seg, 3, nonce, key, mac);
	t2 = rspamd_get_ticks ();

	check_result (key, nonce, mac, begin, end);

	msg_info ("small, medium and large chunks encryption: %.6f", t2 - t1);

	cnt = create_random_split (seg, max_seg, begin, end);
	t1 = rspamd_get_ticks ();
	rspamd_cryptobox_encryptv_nm_inplace (seg, cnt, nonce, key, mac);
	t2 = rspamd_get_ticks ();

	check_result (key, nonce, mac, begin, end);

	msg_info ("random split of %d chunks encryption: %.6f", cnt, t2 - t1);

	cnt = create_realistic_split (seg, max_seg, begin, end);
	t1 = rspamd_get_ticks ();
	rspamd_cryptobox_encryptv_nm_inplace (seg, cnt, nonce, key, mac);
	t2 = rspamd_get_ticks ();

	check_result (key, nonce, mac, begin, end);

	msg_info ("realistic split of %d chunks encryption: %.6f", cnt, t2 - t1);

	for (i = 0; i < random_fuzz_cnt; i ++) {
		ms = ottery_rand_range (i % max_seg * 2) + 1;
		cnt = create_random_split (seg, ms, begin, end);
		t1 = rspamd_get_ticks ();
		rspamd_cryptobox_encryptv_nm_inplace (seg, cnt, nonce, key, mac);
		t2 = rspamd_get_ticks ();

		check_result (key, nonce, mac, begin, end);

		if (i % 1000 == 0) {
			msg_info ("random fuzz iterations: %d", i);
		}
	}
	for (i = 0; i < random_fuzz_cnt; i ++) {
		ms = ottery_rand_range (i % max_seg * 2) + 1;
		cnt = create_realistic_split (seg, ms, begin, end);
		t1 = rspamd_get_ticks ();
		rspamd_cryptobox_encryptv_nm_inplace (seg, cnt, nonce, key, mac);
		t2 = rspamd_get_ticks ();

		check_result (key, nonce, mac, begin, end);

		if (i % 1000 == 0) {
			msg_info ("realistic fuzz iterations: %d", i);
		}
	}
}
