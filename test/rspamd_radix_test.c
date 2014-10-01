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

const gsize max_elts = 50 * 1024;
const gint lookup_cycles = 1 * 1024;

const uint masks[] = {
		8,
		16,
		24,
		32,
		27,
		29,
		19,
		13,
		22
};

struct _tv {
	const char *ip;
	const char *nip;
	const char *m;
	guint32 mask;
	guint8 *addr;
	guint8 *naddr;
	gsize len;
} test_vec[] = {
	{"192.168.1.1", "192.168.1.2", "32", 0, 0, 0, 0},
	{"192.168.1.0", "192.168.2.1", "24", 0, 0, 0, 0},
	{"192.0.0.0", "193.167.2.1", "8", 0, 0, 0, 0},
	{"172.0.0.0", "171.16.1.0", "8", 0, 0, 0, 0},
	{"172.16.0.1", "127.0.0.1", "16", 0, 0, 0, 0},
	{"172.17.1.0", "10.0.0.1", "27", 0, 0, 0, 0},
	{"172.17.1.1", "0.0.0.1", "32", 0, 0, 0, 0},

	/* Some bad data known to cause problem in the past */
	{"191.245.170.246", NULL, "19", 0, 0, 0, 0},
	{"227.88.150.170", NULL, "23", 0, 0, 0, 0},
	{"105.225.182.92", NULL, "24", 0, 0, 0, 0},
	{"223.167.155.240", NULL, "29", 0, 0, 0, 0},
	{"125.241.220.172", NULL, "2", 0, 0, 0, 0},

	/* Mask = 0 */
	{"143.105.181.13", NULL, "8", 0, 0, 0, 0},
	{"113.241.233.86", NULL, "26", 0, 0, 0, 0},
	{"185.187.122.222", NULL, "8", 0, 0, 0, 0},
	{"109.206.26.202", NULL, "12", 0, 0, 0, 0},
	{"130.244.233.150", NULL, "0", 0, 0, 0, 0},

	{NULL, NULL, NULL, 0, 0, 0, 0}
};

static void
rspamd_radix_text_vec (void)
{
	radix_compressed_t *tree = radix_tree_create_compressed ();
	struct _tv *t = &test_vec[0];
	struct in_addr ina;
	struct in6_addr in6a;
	gulong i, val;

	while (t->ip != NULL) {
		t->addr = g_malloc (sizeof (in6a));
		t->naddr = g_malloc (sizeof (in6a));
		if (inet_pton (AF_INET, t->ip, &ina) == 1) {
			memcpy (t->addr, &ina, sizeof (ina));
			t->len = sizeof (ina);
		}
		else if (inet_pton (AF_INET6, t->ip, &in6a) == 1) {
			memcpy (t->addr, &in6a, sizeof (in6a));
			t->len = sizeof (in6a);
		}
		else {
			g_assert (0);
		}
		if (t->nip) {
			if (inet_pton (AF_INET, t->nip, &ina) == 1) {
				memcpy (t->naddr, &ina, sizeof (ina));
			}
			else if (inet_pton (AF_INET6, t->nip, &in6a) == 1) {
				memcpy (t->naddr, &in6a, sizeof (in6a));
			}
			else {
				g_assert (0);
			}
		}

		t->mask = t->len * NBBY - strtoul (t->m, NULL, 10);
		t ++;
	}
	t = &test_vec[0];

	i = 0;
	while (t->ip != NULL) {
		radix_insert_compressed (tree, t->addr, t->len, t->mask, ++i);
		t ++;
	}

	i = 0;
	t = &test_vec[0];
	while (t->ip != NULL) {
		val = radix_find_compressed (tree, t->addr, t->len);
		g_assert (val == ++i);
		//g_assert (val != RADIX_NO_VALUE);
		if (t->nip != NULL) {
			val = radix_find_compressed (tree, t->naddr, t->len);
			g_assert (val != i);
		}
		t ++;
	}

	radix_tree_destroy_compressed (tree);
}

void
rspamd_radix_test_func (void)
{
	radix_tree_t *tree = radix_tree_create ();
	radix_compressed_t *comp_tree = radix_tree_create_compressed ();
	struct {
		guint32 addr;
		guint32 mask;
		guint8 addr6[16];
		guint32 mask6;
	} *addrs;
	gsize nelts, i;
	gint lc;
	gboolean all_good = TRUE;
	struct timespec ts1, ts2;
	double diff;

	/* Test suite for the compressed trie */
	rspamd_radix_text_vec ();

	g_assert (tree != NULL);
	nelts = max_elts;
	/* First of all we generate many elements and push them to the array */
	addrs = g_malloc (nelts * sizeof (addrs[0]));

	for (i = 0; i < nelts; i ++) {
		addrs[i].addr = ottery_rand_uint32 ();
		addrs[i].mask = masks[ottery_rand_range(G_N_ELEMENTS (masks) - 1)];
		ottery_rand_bytes (addrs[i].addr6, sizeof(addrs[i].addr6));
		addrs[i].mask6 = ottery_rand_range(128);
	}

	msg_info ("old radix performance (%z elts)", nelts);
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
	for (lc = 0; lc < lookup_cycles; lc ++) {
		for (i = 0; i < nelts; i ++) {
			g_assert (radix32tree_find (tree, addrs[i].addr) != RADIX_NO_VALUE);
		}
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

	msg_info ("new radix performance (%z elts)", nelts);
	clock_gettime (CLOCK_MONOTONIC, &ts1);
	for (i = 0; i < nelts; i ++) {
		radix_insert_compressed (comp_tree, addrs[i].addr6, sizeof (addrs[i].addr6),
				128 - addrs[i].mask6, i);
	}
	clock_gettime (CLOCK_MONOTONIC, &ts2);
	diff = (ts2.tv_sec - ts1.tv_sec) * 1000. +   /* Seconds */
			(ts2.tv_nsec - ts1.tv_nsec) / 1000000.;  /* Nanoseconds */

	msg_info ("Added %z elements in %.6f ms", nelts, diff);

	clock_gettime (CLOCK_MONOTONIC, &ts1);
	for (lc = 0; lc < lookup_cycles; lc ++) {
		for (i = 0; i < nelts; i ++) {
			if (radix_find_compressed (comp_tree, addrs[i].addr6, sizeof (addrs[i].addr6))
					== RADIX_NO_VALUE) {
				all_good = FALSE;
			}
		}
	}
#if 1
	if (!all_good) {
		for (i = 0; i < nelts; i ++) {
			/* Used to write bad random vector */
			char ipbuf[INET6_ADDRSTRLEN + 1];
			inet_ntop(AF_INET6, addrs[i].addr6, ipbuf, sizeof(ipbuf));
			msg_info("{\"%s\", NULL, \"%ud\", 0, 0, 0, 0},",
					ipbuf,
					addrs[i].mask6);
		}
	}
#endif

	g_assert (all_good);
	clock_gettime (CLOCK_MONOTONIC, &ts2);
	diff = (ts2.tv_sec - ts1.tv_sec) * 1000. +   /* Seconds */
			(ts2.tv_nsec - ts1.tv_nsec) / 1000000.;  /* Nanoseconds */

	msg_info ("Checked %z elements in %.6f ms", nelts, diff);
	radix_tree_destroy_compressed (comp_tree);

	g_free (addrs);
}
