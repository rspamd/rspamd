/* Copyright (c) 2010, Vsevolod Stakhov
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


#ifndef KVSTORAGE_CONFIG_H_
#define KVSTORAGE_CONFIG_H_

#include "config.h"
#include "kvstorage.h"

/* Type of kvstorage cache */
enum kvstorage_cache_type {
	KVSTORAGE_TYPE_CACHE_HASH,
	KVSTORAGE_TYPE_CACHE_RADIX,
#ifdef WITH_JUDY
	KVSTORAGE_TYPE_CACHE_JUDY,
#endif
	KVSTORAGE_TYPE_MAX = 255
};

/* Type of kvstorage backend */
enum kvstorage_backend_type {
	KVSTORAGE_TYPE_BACKEND_NULL = 0,
	KVSTORAGE_TYPE_BACKEND_FILE,
#ifdef WITH_DB
	KVSTORAGE_TYPE_BACKEND_BDB,
#endif
#ifdef WITH_SQLITE
	KVSTORAGE_TYPE_BACKEND_SQLITE,
#endif
	KVSTORAGE_TYPE_BACKEND_MAX = 255
};

/* Type of kvstorage expire */
enum kvstorage_expire_type {
	KVSTORAGE_TYPE_EXPIRE_LRU
};

/* Cache config */
struct kvstorage_cache_config {
	gsize max_elements;
	gsize max_memory;
	enum kvstorage_cache_type type;
};

/* Backend config */
struct kvstorage_backend_config {
	enum kvstorage_backend_type type;
	gchar *filename;
	guint sync_ops;
};


/* Expire config */
struct kvstorage_expire_config {
	enum kvstorage_expire_type type;
};

/* The main keystorage config */
struct kvstorage_config {
	gint id;
	gchar *name;
	struct kvstorage_cache_config cache;
	struct kvstorage_backend_config backend;
	struct kvstorage_expire_config expire;
	struct rspamd_kv_storage *storage;
};

/* Init subparser of kvstorage config */
void init_kvstorage_config (void);

/* Get configuration for kvstorage with specified ID */
struct kvstorage_config* get_kvstorage_config (gint id);

void destroy_kvstorage_config (void);

#endif /* KVSTORAGE_CONFIG_H_ */
