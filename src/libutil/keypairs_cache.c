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

struct rspamd_keypair_elt {
	guchar nm[crypto_box_BEFORENMBYTES];
};

struct rspamd_keypair_cache {
	rspamd_lru_hash_t *hash;
};

struct rspamd_keypair_cache *
rspamd_keypair_cache_new (guint max_items)
{
	struct rspamd_keypair_cache *c;

	g_assert (max_items > 0);

	c = g_slice_alloc (sizeof (*c));
	c->hash = rspamd_lru_hash_new (max_items, -1, g_free, g_free);

	return c;
}

void
rspamd_keypair_cache_process (struct rspamd_keypair_cache *c,
		gpointer lk, gpointer rk)
{
	struct rspamd_http_keypair *kp_local = (struct rspamd_http_keypair *)lk,
			*kp_remote = (struct rspamd_http_keypair *)rk;
	guchar nm[crypto_box_BEFORENMBYTES];

	g_assert (kp_local != NULL);
	g_assert (kp_remote != NULL);

	/*
	 * XXX: at this point we do nothing, since LRU hash is completely broken
	 * and useless for our purposes
	 */
	crypto_box_beforenm (nm, kp_remote->pk, kp_local->sk);
	memcpy (kp_remote->nm, nm, sizeof (nm));
	memcpy (kp_local->nm, nm, sizeof (nm));
}

void
rspamd_keypair_cache_destroy (struct rspamd_keypair_cache *c)
{
	if (c != NULL) {
		rspamd_lru_hash_destroy (c->hash);
		g_slice_free1 (sizeof (*c), c);
	}
}
