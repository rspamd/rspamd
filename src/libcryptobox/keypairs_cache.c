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
#include "keypairs_cache.h"
#include "keypair_private.h"
#include "libutil/util.h"
#include "hash.h"

struct rspamd_keypair_elt {
	struct rspamd_cryptobox_nm *nm;
	guchar pair[rspamd_cryptobox_HASHBYTES * 2];
};

struct rspamd_keypair_cache {
	rspamd_lru_hash_t *hash;
};

static void
rspamd_keypair_destroy (gpointer ptr)
{
	struct rspamd_keypair_elt *elt = (struct rspamd_keypair_elt *)ptr;

	REF_RELEASE (elt->nm);
	g_free (elt);
}

static guint
rspamd_keypair_hash (gconstpointer ptr)
{
	struct rspamd_keypair_elt *elt = (struct rspamd_keypair_elt *)ptr;

	return rspamd_cryptobox_fast_hash (elt->pair, sizeof (elt->pair),
			rspamd_hash_seed ());
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

	c = g_malloc0 (sizeof (*c));
	c->hash = rspamd_lru_hash_new_full (max_items, NULL,
			rspamd_keypair_destroy, rspamd_keypair_hash, rspamd_keypair_equal);

	return c;
}

void
rspamd_keypair_cache_process (struct rspamd_keypair_cache *c,
		struct rspamd_cryptobox_keypair *lk,
		struct rspamd_cryptobox_pubkey *rk)
{
	struct rspamd_keypair_elt search, *new;

	g_assert (lk != NULL);
	g_assert (rk != NULL);
	g_assert (rk->alg == lk->alg);
	g_assert (rk->type == lk->type);
	g_assert (rk->type == RSPAMD_KEYPAIR_KEX);

	memset (&search, 0, sizeof (search));
	memcpy (search.pair, rk->id, rspamd_cryptobox_HASHBYTES);
	memcpy (&search.pair[rspamd_cryptobox_HASHBYTES], lk->id,
			rspamd_cryptobox_HASHBYTES);
	new = rspamd_lru_hash_lookup (c->hash, &search, time (NULL));

	if (rk->nm) {
		REF_RELEASE (rk->nm);
		rk->nm = NULL;
	}

	if (new == NULL) {
		new = g_malloc0 (sizeof (*new));

		if (posix_memalign ((void **)&new->nm, 32, sizeof (*new->nm)) != 0) {
			abort ();
		}

		REF_INIT_RETAIN (new->nm, rspamd_cryptobox_nm_dtor);

		memcpy (new->pair, rk->id, rspamd_cryptobox_HASHBYTES);
		memcpy (&new->pair[rspamd_cryptobox_HASHBYTES], lk->id,
				rspamd_cryptobox_HASHBYTES);
		memcpy (&new->nm->sk_id, lk->id, sizeof (guint64));

		if (rk->alg == RSPAMD_CRYPTOBOX_MODE_25519) {
			struct rspamd_cryptobox_pubkey_25519 *rk_25519 =
					RSPAMD_CRYPTOBOX_PUBKEY_25519(rk);
			struct rspamd_cryptobox_keypair_25519 *sk_25519 =
					RSPAMD_CRYPTOBOX_KEYPAIR_25519(lk);

			rspamd_cryptobox_nm (new->nm->nm, rk_25519->pk, sk_25519->sk, rk->alg);
		}
		else {
			struct rspamd_cryptobox_pubkey_nist *rk_nist =
					RSPAMD_CRYPTOBOX_PUBKEY_NIST(rk);
			struct rspamd_cryptobox_keypair_nist *sk_nist =
					RSPAMD_CRYPTOBOX_KEYPAIR_NIST(lk);

			rspamd_cryptobox_nm (new->nm->nm, rk_nist->pk, sk_nist->sk, rk->alg);
		}

		rspamd_lru_hash_insert (c->hash, new, new, time (NULL), -1);
	}

	g_assert (new != NULL);

	rk->nm = new->nm;
	REF_RETAIN (rk->nm);
}

void
rspamd_keypair_cache_destroy (struct rspamd_keypair_cache *c)
{
	if (c != NULL) {
		rspamd_lru_hash_destroy (c->hash);
		g_free (c);
	}
}
