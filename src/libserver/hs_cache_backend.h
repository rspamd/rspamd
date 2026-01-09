/*
 * Copyright 2025 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef RSPAMD_HS_CACHE_BACKEND_H
#define RSPAMD_HS_CACHE_BACKEND_H

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

struct rspamd_config;
struct ev_loop;

/**
 * Callback for async cache operations
 * @param err error message or NULL on success
 * @param data loaded data (for load operations) or NULL
 * @param len data length
 * @param ud userdata
 */
typedef void (*rspamd_hs_cache_cb_t)(const char *err,
									 const unsigned char *data,
									 gsize len,
									 void *ud);

/**
 * Cache backend operations structure
 */
struct rspamd_hs_cache_backend {
	/**
	 * Save data to cache
	 * @param cache_key unique key for this cache entry
	 * @param platform_id platform identifier
	 * @param data serialized hyperscan database
	 * @param len data length
	 * @param callback completion callback
	 * @param ud userdata for callback
	 */
	void (*save)(const char *cache_key,
				 const char *platform_id,
				 const unsigned char *data,
				 gsize len,
				 rspamd_hs_cache_cb_t callback,
				 void *ud);

	/**
	 * Load data from cache
	 * @param cache_key unique key for this cache entry
	 * @param platform_id platform identifier
	 * @param callback completion callback with data
	 * @param ud userdata for callback
	 */
	void (*load)(const char *cache_key,
				 const char *platform_id,
				 rspamd_hs_cache_cb_t callback,
				 void *ud);

	/**
	 * Check if cache entry exists
	 * @param cache_key unique key
	 * @param platform_id platform identifier
	 * @param callback completion callback (data will be NULL, check err)
	 * @param ud userdata
	 */
	void (*exists)(const char *cache_key,
				   const char *platform_id,
				   rspamd_hs_cache_cb_t callback,
				   void *ud);

	/* Opaque backend context */
	void *ctx;
};

/**
 * Set the global hyperscan cache backend.
 * Called by hs_helper after initializing the Lua backend.
 * @param backend backend operations structure (takes ownership)
 */
void rspamd_hs_cache_set_backend(struct rspamd_hs_cache_backend *backend);

/**
 * Get the current hyperscan cache backend.
 * @return backend or NULL if using default file backend
 */
struct rspamd_hs_cache_backend *rspamd_hs_cache_get_backend(void);

/**
 * Check if a custom (non-file) backend is configured.
 * @return TRUE if custom backend is set
 */
gboolean rspamd_hs_cache_has_custom_backend(void);

/**
 * Free the cache backend
 */
void rspamd_hs_cache_free_backend(void);

typedef struct lua_State lua_State;
/**
 * Set the Lua backend state (called by hs_helper)
 * @param L Lua state
 * @param ref registry reference to the backend object
 * @param platform_id hyperscan platform identifier
 */
void rspamd_hs_cache_set_lua_backend(lua_State *L, int ref, const char *platform_id);

/**
 * Check if Lua backend is available
 * @return TRUE if Lua backend is set
 */
gboolean rspamd_hs_cache_has_lua_backend(void);

/**
 * Initialize Lua HS cache backend in the current process using hs_helper worker
 * configuration (if configured and Lua is available).
 *
 * This is meant to be called from worker initialization after ev_base is ready.
 */
gboolean rspamd_hs_cache_try_init_lua_backend(struct rspamd_config *cfg,
											  struct ev_loop *ev_base);

/**
 * Save data to cache via Lua backend (synchronous)
 * @param cache_key unique cache key (hash)
 * @param data serialized hyperscan data
 * @param len data length
 * @param err error output
 * @return TRUE on success
 */
gboolean rspamd_hs_cache_lua_save(const char *cache_key,
								  const unsigned char *data,
								  gsize len,
								  GError **err);

/**
 * Load data from cache via Lua backend (synchronous)
 * @param cache_key unique cache key (hash)
 * @param data output data (caller must g_free)
 * @param len output data length
 * @param err error output
 * @return TRUE on success (including cache miss with data=NULL)
 */
gboolean rspamd_hs_cache_lua_load(const char *cache_key,
								  unsigned char **data,
								  gsize *len,
								  GError **err);

/**
 * Check if cache entry exists via Lua backend (synchronous)
 * @param cache_key unique cache key (hash)
 * @param err error output
 * @return TRUE if exists
 */
gboolean rspamd_hs_cache_lua_exists(const char *cache_key, GError **err);

/**
 * Async callback type
 * @param success TRUE if operation succeeded
 * @param data loaded data (for load) or NULL
 * @param len data length
 * @param error error message or NULL
 * @param ud userdata
 */
typedef void (*rspamd_hs_cache_async_cb)(gboolean success,
										 const unsigned char *data,
										 gsize len,
										 const char *error,
										 void *ud);

/**
 * Save data to cache via Lua backend (asynchronous)
 * @param cache_key unique cache key (hash)
 * @param data serialized hyperscan data
 * @param len data length
 * @param cb completion callback
 * @param ud userdata
 */
void rspamd_hs_cache_lua_save_async(const char *cache_key,
									const unsigned char *data,
									gsize len,
									rspamd_hs_cache_async_cb cb,
									void *ud);

/**
 * Load data from cache via Lua backend (asynchronous)
 * @param cache_key unique cache key (hash)
 * @param cb completion callback
 * @param ud userdata
 */
void rspamd_hs_cache_lua_load_async(const char *cache_key,
									rspamd_hs_cache_async_cb cb,
									void *ud);

/**
 * Check if cache entry exists via Lua backend (asynchronous)
 * @param cache_key unique cache key (hash)
 * @param cb completion callback (len will be 1 if exists, 0 otherwise)
 * @param ud userdata
 */
void rspamd_hs_cache_lua_exists_async(const char *cache_key,
									  rspamd_hs_cache_async_cb cb,
									  void *ud);

#ifdef __cplusplus
}
#endif

#endif /* RSPAMD_HS_CACHE_BACKEND_H */
