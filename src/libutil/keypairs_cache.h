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
#ifndef KEYPAIRS_CACHE_H_
#define KEYPAIRS_CACHE_H_

#include "config.h"

struct rspamd_keypair_cache;

/**
 * Create new keypair cache of the specified size
 * @param max_items defines maximum count of elements in the cache
 * @return new cache
 */
struct rspamd_keypair_cache * rspamd_keypair_cache_new (guint max_items);


/**
 * Process local and remote keypair setting beforenm value as appropriate
 * @param c cache of keypairs
 * @param lk local key
 * @param rk remote key
 */
void rspamd_keypair_cache_process (struct rspamd_keypair_cache *c,
		gpointer lk, gpointer rk);

/**
 * Destroy old keypair cache
 * @param c cache object
 */
void rspamd_keypair_cache_destroy (struct rspamd_keypair_cache *c);


#endif /* KEYPAIRS_CACHE_H_ */
