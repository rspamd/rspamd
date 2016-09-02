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
#include "fuzzy_backend.h"
#include "fuzzy_backend_redis.h"
#include "redis_pool.h"
#include "contrib/hiredis/hiredis.h"
#include "contrib/hiredis/async.h"

#define REDIS_DEFAULT_PORT 6379
#define REDIS_DEFAULT_OBJECT "fuzzy"
#define REDIS_DEFAULT_TIMEOUT 2.0

struct rspamd_fuzzy_backend_redis {
	struct upstream_list *read_servers;
	struct upstream_list *write_servers;
	const gchar *redis_object;
	const gchar *password;
	const gchar *dbname;
	gdouble timeout;
};

static gboolean
rspamd_redis_try_ucl (struct rspamd_fuzzy_backend_redis *backend,
		const ucl_object_t *obj,
		struct rspamd_config *cfg)
{
	const ucl_object_t *elt, *relt;

	elt = ucl_object_lookup_any (obj, "read_servers", "servers", NULL);

	if (elt == NULL) {
		return FALSE;
	}

	backend->read_servers = rspamd_upstreams_create (cfg->ups_ctx);
	if (!rspamd_upstreams_from_ucl (backend->read_servers, elt,
			REDIS_DEFAULT_PORT, NULL)) {
		msg_err_config ("cannot get read servers configuration");
		return FALSE;
	}

	relt = elt;

	elt = ucl_object_lookup (obj, "write_servers");
	if (elt == NULL) {
		/* Use read servers as write ones */
		g_assert (relt != NULL);
		backend->write_servers = rspamd_upstreams_create (cfg->ups_ctx);
		if (!rspamd_upstreams_from_ucl (backend->write_servers, relt,
				REDIS_DEFAULT_PORT, NULL)) {
			msg_err_config ("cannot get write servers configuration");
			return FALSE;
		}
	}
	else {
		backend->write_servers = rspamd_upstreams_create (cfg->ups_ctx);
		if (!rspamd_upstreams_from_ucl (backend->write_servers, elt,
				REDIS_DEFAULT_PORT, NULL)) {
			msg_err_config ("cannot get write servers configuration");
			rspamd_upstreams_destroy (backend->write_servers);
			backend->write_servers = NULL;
		}
	}

	elt = ucl_object_lookup (obj, "prefix");
	if (elt == NULL || ucl_object_type (elt) != UCL_STRING) {
		backend->redis_object = REDIS_DEFAULT_OBJECT;
	}
	else {
		backend->redis_object = ucl_object_tostring (elt);
	}

	elt = ucl_object_lookup (obj, "timeout");
	if (elt) {
		backend->timeout = ucl_object_todouble (elt);
	}
	else {
		backend->timeout = REDIS_DEFAULT_TIMEOUT;
	}

	elt = ucl_object_lookup (obj, "password");
	if (elt) {
		backend->password = ucl_object_tostring (elt);
	}
	else {
		backend->password = NULL;
	}

	elt = ucl_object_lookup_any (obj, "db", "database", "dbname", NULL);
	if (elt) {
		backend->dbname = ucl_object_tostring (elt);
	}
	else {
		backend->dbname = NULL;
	}

	return TRUE;
}

void*
rspamd_fuzzy_backend_init_redis (struct rspamd_fuzzy_backend *bk,
		const ucl_object_t *obj, struct rspamd_config *cfg, GError **err)
{

}

void
rspamd_fuzzy_backend_check_redis (struct rspamd_fuzzy_backend *bk,
		const struct rspamd_fuzzy_cmd *cmd,
		rspamd_fuzzy_check_cb cb, void *ud,
		void *subr_ud)
{

}

void
rspamd_fuzzy_backend_update_redis (struct rspamd_fuzzy_backend *bk,
		GQueue *updates, const gchar *src,
		rspamd_fuzzy_update_cb cb, void *ud,
		void *subr_ud)
{

}

void
rspamd_fuzzy_backend_count_redis (struct rspamd_fuzzy_backend *bk,
		rspamd_fuzzy_count_cb cb, void *ud,
		void *subr_ud)
{

}
void
rspamd_fuzzy_backend_version_redis (struct rspamd_fuzzy_backend *bk,
		const gchar *src,
		rspamd_fuzzy_version_cb cb, void *ud,
		void *subr_ud)
{

}

const gchar*
rspamd_fuzzy_backend_id_redis (struct rspamd_fuzzy_backend *bk,
		void *subr_ud)
{

}

void
rspamd_fuzzy_backend_expire_redis (struct rspamd_fuzzy_backend *bk,
		void *subr_ud)
{

}

void
rspamd_fuzzy_backend_close_redis (struct rspamd_fuzzy_backend *bk,
		void *subr_ud)
{

}
