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
#include "keypairs_cache.h"
#include "keypair_private.h"
#include "hash.h"
#include "xxhash.h"

struct rspamd_keypair_elt {
	guchar nm[rspamd_cryptobox_MAX_NMBYTES];
	guchar pair[rspamd_cryptobox_MAX_PKBYTES + rspamd_cryptobox_MAX_SKBYTES];
};

struct rspamd_keypair_cache {
	rspamd_lru_hash_t *hash;
};

static void
rspamd_keypair_destroy (gpointer ptr)
{
	struct rspamd_keypair_elt *elt = (struct rspamd_keypair_elt *)ptr;

	rspamd_explicit_memzero (elt, sizeof (*elt));
	g_slice_free1 (sizeof (*elt), elt);
}

static guint
rspamd_keypair_hash (gconstpointer ptr)
{
	struct rspamd_keypair_elt *elt = (struct rspamd_keypair_elt *)ptr;

	return XXH64 (elt->pair, sizeof (elt->pair), rspamd_hash_seed ());
}

static gboolean
rspamd_keypair_equal (gconstpointer p1, gconstpointer p2)
{
	struct rspamd_keypair_elt *e1 = (struct rspamd_keypair_elt *)p1,
			*e2 = (struct rspamd_keypair_elt *)p2;

	return memcmp (e1->pair, e2->pair, sizeof (e1->pair)) == 0;
}

struct rspamd_keypair_cache *
rspamd_keypair_cache_new (guint max_items)
{
	struct rspamd_keypair_cache *c;

	g_assert (max_items > 0);

	c = g_slice_alloc (sizeof (*c));
	c->hash = rspamd_lru_hash_new_full (max_items, -1, NULL,
			rspamd_keypair_destroy, rspamd_keypair_hash, rspamd_keypair_equal);

	return c;
}

void
rspamd_keypair_cache_process (struct rspamd_keypair_cache *c,
		gpointer lk, gpointer rk)
{
	struct rspamd_http_keypair *kp_local = (struct rspamd_http_keypair *)lk,
			*kp_remote = (struct rspamd_http_keypair *)rk;
	struct rspamd_keypair_elt search, *new;

	g_assert (kp_local != NULL);
	g_assert (kp_remote != NULL);

	memset (&search, 0, sizeof (search));
	memcpy (search.pair, kp_remote->pk, rspamd_cryptobox_pk_bytes (RSPAMD_CRYPTOBOX_MODE_25519));
	memcpy (&search.pair[rspamd_cryptobox_MAX_PKBYTES], kp_local->sk,
			rspamd_cryptobox_sk_bytes (RSPAMD_CRYPTOBOX_MODE_25519));
	new = rspamd_lru_hash_lookup (c->hash, &search, time (NULL));

	if (new == NULL) {
		new = g_slice_alloc0 (sizeof (*new));
		memcpy (new->pair, kp_remote->pk, rspamd_cryptobox_pk_bytes (RSPAMD_CRYPTOBOX_MODE_25519));
		memcpy (&new->pair[rspamd_cryptobox_MAX_PKBYTES], kp_local->sk,
				rspamd_cryptobox_sk_bytes (RSPAMD_CRYPTOBOX_MODE_25519));
		rspamd_cryptobox_nm (new->nm, kp_remote->pk, kp_local->sk, RSPAMD_CRYPTOBOX_MODE_25519);
		rspamd_lru_hash_insert (c->hash, new, new, time (NULL), -1);
	}

	g_assert (new != NULL);

	memcpy (kp_remote->nm, new->nm, rspamd_cryptobox_nm_bytes (RSPAMD_CRYPTOBOX_MODE_25519));
	kp_remote->has_nm = TRUE;
#if 0
	memcpy (kp_local->nm, new->nm, rspamd_cryptobox_NMBYTES);
#endif
}

void
rspamd_keypair_cache_destroy (struct rspamd_keypair_cache *c)
{
	if (c != NULL) {
		rspamd_lru_hash_destroy (c->hash);
		g_slice_free1 (sizeof (*c), c);
	}
}
