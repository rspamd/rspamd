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

#include "config.h"
#include "main.h"
#include "radix.h"
#include "ottery.h"

const gsize max_elts = 5 * 1024 * 1024;

struct _tv {
	const char *ip;
	const char *m;
	guint32 mask;
	guint32 addr;
} test_vec[] = {
	{"192.168.1.1", "32", 0, 0},
	{"192.168.1.1", "24", 0, 0},
	{"192.168.1.1", "8", 0, 0},
	{"172.16.1.1", "8", 0, 0},
	{"172.16.1.1", "16", 0, 0},
	{"172.16.1.1", "24", 0, 0},
	{"8.8.8.8", "1", 0, 0},
	{NULL, NULL, 0, 0}
};

static void
rspamd_radix_text_vec (void)
{
	radix_compressed_t *tree = radix_tree_create_compressed ();
	struct _tv *t = &test_vec[0];
	struct in_addr ina;

	while (t->ip != NULL) {
		inet_aton (t->ip, &ina);
		t->addr = ina.s_addr;
		t->mask = strtoul (t->m, NULL, 10);
		t ++;
	}
	t = &test_vec[0];

	while (t->ip != NULL) {
		radix_insert_compressed (tree, &t->addr, sizeof (guint32), 32 - t->mask, 1);
		t ++;
	}

	t = &test_vec[0];
	while (t->ip != NULL) {
		g_assert (radix_find_compressed (tree, &t->addr, sizeof (guint32))
						!= RADIX_NO_VALUE);
		t ++;
	}
}

void
rspamd_radix_test_func (void)
{
	radix_tree_t *tree = radix_tree_create ();
	struct {
		guint32 addr;
		guint32 mask;
	} *addrs;
	gsize nelts, i;
	struct timespec ts1, ts2;
	double diff;

	g_assert (tree != NULL);
	nelts = max_elts;
	/* First of all we generate many elements and push them to the array */
	addrs = g_malloc (nelts * sizeof (addrs[0]));

	for (i = 0; i < nelts; i ++) {
		addrs[i].addr = ottery_rand_uint32 ();
		addrs[i].mask = ottery_rand_range (32);
	}

	clock_gettime (CLOCK_MONOTONIC, &ts1);
	for (i = 0; i < nelts; i ++) {
		guint32 mask = G_MAXUINT32 << (32 - addrs[i].mask);
		radix32tree_insert (tree, addrs[i].addr, mask, 1);
	}
	clock_gettime (CLOCK_MONOTONIC, &ts2);
	diff = (ts2.tv_sec - ts1.tv_sec) * 1000. +   /* Seconds */
		(ts2.tv_nsec - ts1.tv_nsec) / 1000000.;  /* Nanoseconds */

	msg_info ("Added %z elements in %.6f ms", nelts, diff);

	clock_gettime (CLOCK_MONOTONIC, &ts1);
	for (i = 0; i < nelts; i ++) {
		g_assert (radix32tree_find (tree, addrs[i].addr) != RADIX_NO_VALUE);
	}
	clock_gettime (CLOCK_MONOTONIC, &ts2);
	diff = (ts2.tv_sec - ts1.tv_sec) * 1000. +   /* Seconds */
			(ts2.tv_nsec - ts1.tv_nsec) / 1000000.;  /* Nanoseconds */

	msg_info ("Checked %z elements in %.6f ms", nelts, diff);

	clock_gettime (CLOCK_MONOTONIC, &ts1);
	for (i = 0; i < nelts; i ++) {
		radix32tree_delete (tree, addrs[i].addr, addrs[i].mask);
	}
	clock_gettime (CLOCK_MONOTONIC, &ts2);
	diff = (ts2.tv_sec - ts1.tv_sec) * 1000. +   /* Seconds */
			(ts2.tv_nsec - ts1.tv_nsec) / 1000000.;  /* Nanoseconds */

	msg_info ("Deleted %z elements in %.6f ms", nelts, diff);

	radix_tree_free (tree);
	rspamd_radix_text_vec ();
	radix_compressed_t *comp_tree = radix_tree_create_compressed ();

	clock_gettime (CLOCK_MONOTONIC, &ts1);
	for (i = 0; i < nelts; i ++) {
		radix_insert_compressed (comp_tree, &addrs[i].addr, sizeof (guint32),
				32 - addrs[i].mask, 1);
	}
	clock_gettime (CLOCK_MONOTONIC, &ts2);
	diff = (ts2.tv_sec - ts1.tv_sec) * 1000. +   /* Seconds */
			(ts2.tv_nsec - ts1.tv_nsec) / 1000000.;  /* Nanoseconds */

	msg_info ("Added %z elements in %.6f ms", nelts, diff);

	clock_gettime (CLOCK_MONOTONIC, &ts1);
	for (i = 0; i < nelts; i ++) {
		g_assert (radix_find_compressed (comp_tree, &addrs[i].addr, sizeof (guint32))
				!= RADIX_NO_VALUE);
	}
	clock_gettime (CLOCK_MONOTONIC, &ts2);
	diff = (ts2.tv_sec - ts1.tv_sec) * 1000. +   /* Seconds */
			(ts2.tv_nsec - ts1.tv_nsec) / 1000000.;  /* Nanoseconds */

	msg_info ("Checked %z elements in %.6f ms", nelts, diff);

	g_free (addrs);
}
