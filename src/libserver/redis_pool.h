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
#ifndef SRC_LIBSERVER_REDIS_POOL_H_
#define SRC_LIBSERVER_REDIS_POOL_H_

#include "config.h"

#ifdef  __cplusplus
extern "C" {
#endif
struct rspamd_config;
struct redisAsyncContext;
struct ev_loop;

/**
 * Creates new redis pool
 * @return
 */
void* rspamd_redis_pool_init (void);

/**
 * Configure redis pool and binds it to a specific event base
 * @param cfg
 * @param ev_base
 */
void rspamd_redis_pool_config (void *pool,
							   struct rspamd_config *cfg,
							   struct ev_loop *ev_base);


/**
 * Create or reuse the specific redis connection
 * @param pool
 * @param db
 * @param password
 * @param ip
 * @param port
 * @return
 */
struct redisAsyncContext *rspamd_redis_pool_connect (
		void *pool,
		const gchar *db, const gchar *password,
		const char *ip, int port);

enum rspamd_redis_pool_release_type {
	RSPAMD_REDIS_RELEASE_DEFAULT = 0,
	RSPAMD_REDIS_RELEASE_FATAL = 1,
	RSPAMD_REDIS_RELEASE_ENFORCE
};

/**
 * Release a connection to the pool
 * @param pool
 * @param ctx
 */
void rspamd_redis_pool_release_connection (void *pool,
										   struct redisAsyncContext *ctx,
										   enum rspamd_redis_pool_release_type how);

/**
 * Stops redis pool and destroys it
 * @param pool
 */
void rspamd_redis_pool_destroy (void *pool);

/**
 * Missing in hiredis
 * @param type
 * @return
 */
const gchar *rspamd_redis_type_to_string (int type);

#ifdef  __cplusplus
}
#endif

#endif /* SRC_LIBSERVER_REDIS_POOL_H_ */
