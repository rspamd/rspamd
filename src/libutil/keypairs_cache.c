/*
 * Copyright (c) 2015, Vsevolod Stakhov
 *
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
#include "keypairs_cache.h"
#include "keypair_private.h"
#include "hash.h"
#include "xxhash.h"

struct rspamd_keypair_elt {
	guchar nm[crypto_box_BEFORENMBYTES];
	guchar pair[crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES];
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

	return XXH32 (elt->pair, sizeof (elt->pair), 0xdeadbabe);
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

	memcpy (search.pair, kp_remote->pk, crypto_box_PUBLICKEYBYTES);
	memcpy (&search.pair[crypto_box_PUBLICKEYBYTES], kp_local->sk,
			crypto_box_SECRETKEYBYTES);
	new = rspamd_lru_hash_lookup (c->hash, &search, time (NULL));

	if (new == NULL) {
		new = g_slice_alloc (sizeof (*new));
		memcpy (new->pair, kp_remote->pk, crypto_box_PUBLICKEYBYTES);
		memcpy (&new->pair[crypto_box_PUBLICKEYBYTES], kp_local->sk,
				crypto_box_SECRETKEYBYTES);
		crypto_box_beforenm (new->nm, kp_remote->pk, kp_local->sk);
		rspamd_lru_hash_insert (c->hash, new, new, time (NULL), -1);
	}

	g_assert (new != NULL);

	memcpy (kp_remote->nm, new->nm, crypto_box_BEFORENMBYTES);
	memcpy (kp_local->nm, new->nm, crypto_box_BEFORENMBYTES);
}

void
rspamd_keypair_cache_destroy (struct rspamd_keypair_cache *c)
{
	if (c != NULL) {
		rspamd_lru_hash_destroy (c->hash);
		g_slice_free1 (sizeof (*c), c);
	}
}
