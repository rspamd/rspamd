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
#include "radix.h"
#include "ottery.h"
#include "btrie.h"

const gsize max_elts = 500 * 1024;
const gint lookup_cycles = 1 * 1024;
const gint lookup_divisor = 10;

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

	/* Close ip addresses */
	{"1.2.3.1",  NULL, "32",  0, 0, 0, 0},
	{"1.2.3.2",  NULL, "32", 0, 0, 0, 0},
	{"1.2.3.3", NULL, "32",  0, 0, 0, 0},
	{"1.2.3.4", NULL, "32", 0, 0, 0, 0},

	{NULL, NULL, NULL, 0, 0, 0, 0}
};

static void
rspamd_radix_test_vec (void)
{
	radix_compressed_t *tree = radix_create_compressed ();
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
		/* g_assert (val != RADIX_NO_VALUE); */
		if (t->nip != NULL) {
			val = radix_find_compressed (tree, t->naddr, t->len);
			g_assert (val != i);
		}
		t ++;
	}

	radix_destroy_compressed (tree);
}

static void
rspamd_btrie_test_vec (void)
{
	rspamd_mempool_t *pool;
	struct btrie *tree;
	struct _tv *t = &test_vec[0];
	struct in_addr ina;
	struct in6_addr in6a;
	gsize i;
	gpointer val;

	pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), "btrie");
	tree = btrie_init (pool);

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

		t->mask = strtoul (t->m, NULL, 10);
		t ++;
	}
	t = &test_vec[0];

	i = 0;
	while (t->ip != NULL) {
		g_assert (btrie_add_prefix (tree, t->addr, t->mask,
				GSIZE_TO_POINTER (++i)) == BTRIE_OKAY);
		t ++;
	}

	i = 0;
	t = &test_vec[0];
	while (t->ip != NULL) {
		val = btrie_lookup (tree, t->addr, t->len * NBBY);
		i ++;

		g_assert (GPOINTER_TO_SIZE (val) == i);
		if (t->nip != NULL) {
			val = btrie_lookup (tree, t->naddr, t->len * NBBY);
			g_assert (GPOINTER_TO_SIZE (val) != i);
		}
		t ++;
	}
}

void
rspamd_radix_test_func (void)
{
	struct btrie *btrie;
	rspamd_mempool_t *pool;
	radix_compressed_t *comp_tree = radix_create_compressed ();
	struct {
		guint32 addr;
		guint32 mask;
		guint8 addr6[16];
		guint32 mask6;
	} *addrs;
	gsize nelts, i, check;
	gint lc;
	gboolean all_good = TRUE;
	gdouble ts1, ts2;
	double diff;

	/* Test suite for the compressed trie */

	rspamd_btrie_test_vec ();
	rspamd_radix_test_vec ();

	nelts = max_elts;
	/* First of all we generate many elements and push them to the array */
	addrs = g_malloc (nelts * sizeof (addrs[0]));

	for (i = 0; i < nelts; i ++) {
		addrs[i].addr = ottery_rand_uint32 ();
		addrs[i].mask = masks[ottery_rand_range(G_N_ELEMENTS (masks) - 1)];
		ottery_rand_bytes (addrs[i].addr6, sizeof(addrs[i].addr6));
		addrs[i].mask6 = ottery_rand_range(128);
	}

	pool = rspamd_mempool_new (65536, "btrie");
	btrie = btrie_init (pool);
	msg_info ("btrie performance (%z elts)", nelts);

	ts1 = rspamd_get_ticks ();
	for (i = 0; i < nelts; i ++) {
		btrie_add_prefix (btrie, addrs[i].addr6,
				addrs[i].mask6, GSIZE_TO_POINTER (i + 1));
	}
	ts2 = rspamd_get_ticks ();
	diff = (ts2 - ts1) * 1000.0;

	msg_info ("Added %hz elements in %.6f ms", nelts, diff);

	ts1 = rspamd_get_ticks ();
	for (lc = 0; lc < lookup_cycles && all_good; lc ++) {
		for (i = 0; i < nelts / lookup_divisor; i ++) {
			check = ottery_rand_range (nelts - 1);

			if (btrie_lookup (btrie, addrs[check].addr6, sizeof (addrs[check].addr6))
					== NULL) {
				char ipbuf[INET6_ADDRSTRLEN + 1];

				all_good = FALSE;

				inet_ntop(AF_INET6, addrs[check].addr6, ipbuf, sizeof(ipbuf));
				msg_info("BAD btrie: {\"%s\", NULL, \"%ud\", 0, 0, 0, 0},",
						ipbuf,
						addrs[check].mask6);
				all_good = FALSE;
			}
		}
	}
	g_assert (all_good);
	ts2 = rspamd_get_ticks ();
	diff = (ts2 - ts1) * 1000.0;

	msg_info ("Checked %hz elements in %.6f ms",
			nelts * lookup_cycles / lookup_divisor, diff);

	msg_info ("new radix performance (%z elts)", nelts);
	ts1 = rspamd_get_ticks ();

	for (i = 0; i < nelts; i ++) {
		radix_insert_compressed (comp_tree, addrs[i].addr6, sizeof (addrs[i].addr6),
				128 - addrs[i].mask6, i + 1);
	}

	ts2 = rspamd_get_ticks ();
	diff = (ts2 - ts1) * 1000.0;

	msg_info ("Added %hz elements in %.6f ms", nelts, diff);

	ts1 = rspamd_get_ticks ();
	for (lc = 0; lc < lookup_cycles && all_good; lc ++) {
		for (i = 0; i < nelts / lookup_divisor; i ++) {
			check = ottery_rand_range (nelts - 1);

			if (radix_find_compressed (comp_tree, addrs[check].addr6,
					sizeof (addrs[check].addr6))
					== RADIX_NO_VALUE) {
				char ipbuf[INET6_ADDRSTRLEN + 1];

				all_good = FALSE;

				inet_ntop(AF_INET6, addrs[check].addr6, ipbuf, sizeof(ipbuf));
				msg_info("BAD: {\"%s\", NULL, \"%ud\", 0, 0, 0, 0},",
						ipbuf,
						addrs[check].mask6);
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
	ts2 = rspamd_get_ticks ();
	diff = (ts2 - ts1) * 1000.0;

	msg_info ("Checked %hz elements in %.6f ms",
			nelts * lookup_cycles / lookup_divisor, diff);
	radix_destroy_compressed (comp_tree);

	g_free (addrs);
}
