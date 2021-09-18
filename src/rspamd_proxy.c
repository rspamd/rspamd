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
#include "libutil/util.h"
#include "libserver/maps/map.h"
#include "libutil/upstream.h"
#include "libserver/http/http_connection.h"
#include "libserver/http/http_private.h"
#include "libserver/protocol.h"
#include "libserver/protocol_internal.h"
#include "libserver/cfg_file.h"
#include "libserver/url.h"
#include "libserver/dns.h"
#include "libmime/message.h"
#include "rspamd.h"
#include "libserver/worker_util.h"
#include "worker_private.h"
#include "lua/lua_common.h"
#include "keypairs_cache.h"
#include "libstat/stat_api.h"
#include "ottery.h"
#include "unix-std.h"
#include "libserver/milter.h"
#include "libserver/milter_internal.h"
#include "libmime/lang_detection.h"

#include <math.h>

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h> /* for TCP_NODELAY */
#endif

#ifdef SYS_ZSTD
#  include "zstd.h"
#else
#  include "contrib/zstd/zstd.h"
#endif

/* Rotate keys each minute by default */
#define DEFAULT_ROTATION_TIME 60.0
#define DEFAULT_RETRIES 5

#define msg_err_session(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        session->pool->tag.tagname, session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_session(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        session->pool->tag.tagname, session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_session(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        session->pool->tag.tagname, session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

#define msg_debug_session(...)  rspamd_conditional_debug_fast (NULL, session->client_addr, \
        rspamd_proxy_log_id, "proxy", session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(proxy)

gpointer init_rspamd_proxy (struct rspamd_config *cfg);
void start_rspamd_proxy (struct rspamd_worker *worker);

worker_t rspamd_proxy_worker = {
	"rspamd_proxy",               /* Name */
	init_rspamd_proxy,            /* Init function */
	start_rspamd_proxy,           /* Start function */
	RSPAMD_WORKER_HAS_SOCKET | RSPAMD_WORKER_KILLABLE | RSPAMD_WORKER_SCANNER,
	RSPAMD_WORKER_SOCKET_TCP,    /* TCP socket */
	RSPAMD_WORKER_VER
};

struct rspamd_http_upstream {
	gchar *name;
	gchar *settings_id;
	struct upstream_list *u;
	struct rspamd_cryptobox_pubkey *key;
	gdouble timeout;
	gint parser_from_ref;
	gint parser_to_ref;
	gboolean local;
	gboolean self_scan;
	gboolean compress;
};

struct rspamd_http_mirror {
	gchar *name;
	gchar *settings_id;
	struct upstream_list *u;
	struct rspamd_cryptobox_pubkey *key;
	gdouble prob;
	gdouble timeout;
	gint parser_from_ref;
	gint parser_to_ref;
	gboolean local;
	gboolean compress;
};

static const guint64 rspamd_rspamd_proxy_magic = 0xcdeb4fd1fc351980ULL;

struct rspamd_proxy_ctx {
	guint64 magic;
	/* Events base */
	struct ev_loop *event_loop;
	/* DNS resolver */
	struct rspamd_dns_resolver *resolver;
	/* Config */
	struct rspamd_config *cfg;
	/* END OF COMMON PART */
	gdouble timeout;
	/* Encryption key for clients */
	struct rspamd_cryptobox_keypair *key;
	/* HTTP context */
	struct rspamd_http_context *http_ctx;
	/* Upstreams to use */
	GHashTable *upstreams;
	/* Mirrors to send traffic to */
	GPtrArray *mirrors;
	/* Default upstream */
	struct rspamd_http_upstream *default_upstream;
	lua_State *lua_state;
	/* Array of callback functions called on end of scan to compare results */
	GArray *cmp_refs;
	/* Maximum count for retries */
	guint max_retries;
	/* If we have self_scanning backends, we need to work as a normal worker */
	gboolean has_self_scan;
	/* It is not HTTP but milter proxy */
	gboolean milter;
	/* Discard messages instead of rejecting them */
	gboolean discard_on_reject;
	/* Quarantine messages instead of rejecting them */
	gboolean quarantine_on_reject;
	/* Milter spam header */
	gchar *spam_header;
	/* CA name that can be used for client certificates */
	gchar *client_ca_name;
	/* Milter rejection message */
	gchar *reject_message;
	/* Sessions cache */
	void *sessions_cache;
	struct rspamd_milter_context milter_ctx;
	/* Language detector */
	struct rspamd_lang_detector *lang_det;
};

enum rspamd_backend_flags {
	RSPAMD_BACKEND_REPLIED = 1 << 0,
	RSPAMD_BACKEND_CLOSED = 1 << 1,
	RSPAMD_BACKEND_PARSED = 1 << 2,
};

struct rspamd_proxy_session;

struct rspamd_proxy_backend_connection {
	const gchar *name;
	struct rspamd_cryptobox_keypair *local_key;
	struct rspamd_cryptobox_pubkey *remote_key;
	struct upstream *up;
	struct rspamd_http_connection *backend_conn;
	ucl_object_t *results;
	const gchar *err;
	struct rspamd_proxy_session *s;
	gint backend_sock;
	ev_tstamp timeout;
	enum rspamd_backend_flags flags;
	gint parser_from_ref;
	gint parser_to_ref;
	struct rspamd_task *task;
};

enum rspamd_proxy_legacy_support {
	LEGACY_SUPPORT_NO = 0,
	LEGACY_SUPPORT_RSPAMC,
	LEGACY_SUPPORT_SPAMC
};

struct rspamd_proxy_session {
	struct rspamd_worker *worker;
	rspamd_mempool_t *pool;
	struct rspamd_proxy_ctx *ctx;
	rspamd_inet_addr_t *client_addr;
	struct rspamd_http_connection *client_conn;
	struct rspamd_milter_session *client_milter_conn;
	struct rspamd_http_upstream *backend;
	gpointer map;
	gchar *fname;
	gpointer shmem_ref;
	struct rspamd_proxy_backend_connection *master_conn;
	struct rspamd_http_message *client_message;
	GPtrArray *mirror_conns;
	gsize map_len;
	gint client_sock;
	enum rspamd_proxy_legacy_support legacy_support;
	gint retries;
	ref_entry_t ref;
};

static gboolean proxy_send_master_message (struct rspamd_proxy_session *session);

static GQuark
rspamd_proxy_quark (void)
{
	return g_quark_from_static_string ("rspamd-proxy");
}

static gboolean
rspamd_proxy_parse_lua_parser (lua_State *L, const ucl_object_t *obj,
		gint *ref_from, gint *ref_to, GError **err)
{
	const gchar *lua_script;
	gsize slen;
	gint err_idx, ref_idx;
	gboolean has_ref = FALSE;

	g_assert (obj != NULL);
	g_assert (ref_from != NULL);
	g_assert (ref_to != NULL);

	*ref_from = -1;
	*ref_to = -1;

	lua_script = ucl_object_tolstring (obj, &slen);
	lua_pushcfunction (L, &rspamd_lua_traceback);
	err_idx = lua_gettop (L);

	/* Load data */
	if (luaL_loadbuffer (L, lua_script, slen, "proxy parser") != 0) {
		g_set_error (err,
				rspamd_proxy_quark (),
				EINVAL,
				"cannot load lua parser script: %s",
				lua_tostring (L, -1));
		lua_settop (L, 0); /* Error function */

		return FALSE;
	}

	/* Now do it */
	if (lua_pcall (L, 0, 1, err_idx) != 0) {
		g_set_error (err,
				rspamd_proxy_quark (),
				EINVAL,
				"cannot init lua parser script: %s",
				lua_tostring (L, -1));
		lua_settop (L, 0);

		return FALSE;
	}

	if (lua_istable (L, -1)) {
		/*
		 * We have a table, so we check for two keys:
		 * 'from' -> function
		 * 'to' -> function
		 *
		 * From converts parent request to a client one
		 * To converts client request to a parent one
		 */
		lua_pushstring (L, "from");
		lua_gettable (L, -2);

		if (lua_isfunction (L, -1)) {
			ref_idx = luaL_ref (L, LUA_REGISTRYINDEX);
			*ref_from = ref_idx;
			has_ref = TRUE;
		}

		lua_pushstring (L, "to");
		lua_gettable (L, -2);

		if (lua_isfunction (L, -1)) {
			ref_idx = luaL_ref (L, LUA_REGISTRYINDEX);
			*ref_to = ref_idx;
			has_ref = TRUE;
		}
	}
	else if (!lua_isfunction (L, -1)) {
		g_set_error (err,
				rspamd_proxy_quark (),
				EINVAL,
				"cannot init lua parser script: "
				"must return function");
		lua_settop (L, 0);

		return FALSE;
	}
	else {
		/* Just parser from protocol */
		ref_idx = luaL_ref (L, LUA_REGISTRYINDEX);
		*ref_from = ref_idx;
		lua_settop (L, 0);
		has_ref = TRUE;
	}

	return has_ref;
}

static gboolean
rspamd_proxy_parse_upstream (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	const ucl_object_t *elt;
	struct rspamd_http_upstream *up = NULL;
	struct rspamd_proxy_ctx *ctx;
	struct rspamd_rcl_struct_parser *pd = ud;
	lua_State *L;

	ctx = pd->user_struct;
	L = ctx->lua_state;

	if (ucl_object_type (obj) != UCL_OBJECT) {
		g_set_error (err, rspamd_proxy_quark (), 100,
				"upstream option must be an object");

		return FALSE;
	}

	up = rspamd_mempool_alloc0 (pool, sizeof (*up));

	elt = ucl_object_lookup (obj, "name");
	if (elt == NULL) {

		if (ucl_object_key (obj)) {
			if (strcmp (ucl_object_key (obj), "upstream") == 0) {
				/* Iterate over the object and find upstream elements */
				ucl_object_iter_t it = NULL;
				const ucl_object_t *cur;
				gboolean ret = TRUE;

				while ((cur = ucl_object_iterate (obj, &it, true)) != NULL) {
					if (!rspamd_proxy_parse_upstream (pool, cur, ud,
							section, err)) {
						ret = FALSE;
					}
				}

				return ret;
			}
			else {
				/* Inside upstream */
				up->name = rspamd_mempool_strdup (pool, ucl_object_key (obj));
			}
		}
		else {
			g_set_error (err, rspamd_proxy_quark (), 100,
					"upstream option must have some name definition");

			return FALSE;
		}
	}
	else {
		up->name = rspamd_mempool_strdup (pool, ucl_object_tostring (elt));
	}

	up->parser_from_ref = -1;
	up->parser_to_ref = -1;
	up->timeout = ctx->timeout;

	elt = ucl_object_lookup (obj, "key");
	if (elt != NULL) {
		up->key = rspamd_pubkey_from_base32 (ucl_object_tostring (elt), 0,
				RSPAMD_KEYPAIR_KEX, RSPAMD_CRYPTOBOX_MODE_25519);

		if (up->key == NULL) {
			g_set_error (err, rspamd_proxy_quark (), 100,
					"cannot read upstream key");

			goto err;
		}

		rspamd_mempool_add_destructor (pool,
				(rspamd_mempool_destruct_t)rspamd_pubkey_unref, up->key);
	}

	elt = ucl_object_lookup (obj, "self_scan");
	if (elt && ucl_object_toboolean (elt)) {
		up->self_scan = TRUE;
		ctx->has_self_scan = TRUE;
	}

	elt = ucl_object_lookup_any (obj, "compress", "compression", NULL);
	if (elt && ucl_object_toboolean (elt)) {
		up->compress = TRUE;
	}

	elt = ucl_object_lookup (obj, "hosts");

	if (elt == NULL && !up->self_scan) {
		g_set_error (err, rspamd_proxy_quark (), 100,
				"upstream option must have some hosts definition");

		goto err;
	}

	if (elt) {
		up->u = rspamd_upstreams_create (ctx->cfg->ups_ctx);

		if (!rspamd_upstreams_from_ucl (up->u, elt, 11333, NULL)) {
			g_set_error (err, rspamd_proxy_quark (), 100,
					"upstream has bad hosts definition");

			goto err;
		}

		rspamd_mempool_add_destructor (pool,
				(rspamd_mempool_destruct_t)rspamd_upstreams_destroy, up->u);
	}

	elt = ucl_object_lookup (obj, "default");
	if (elt) {
		if (ucl_object_toboolean (elt)) {
			ctx->default_upstream = up;
		}
	}
	else if (up->self_scan) {
		ctx->default_upstream = up;
	}


	elt = ucl_object_lookup (obj, "local");
	if (elt && ucl_object_toboolean (elt)) {
		up->local = TRUE;
	}

	elt = ucl_object_lookup (obj, "timeout");
	if (elt) {
		ucl_object_todouble_safe (elt, &up->timeout);
	}

	elt = ucl_object_lookup_any (obj, "settings", "settings_id", NULL);
	if (elt && ucl_object_type (elt) == UCL_STRING) {
		up->settings_id = rspamd_mempool_strdup (pool, ucl_object_tostring (elt));
	}

	/*
	 * Accept lua function here in form
	 * fun :: String -> UCL
	 */
	elt = ucl_object_lookup (obj, "parser");
	if (elt) {
		if (!rspamd_proxy_parse_lua_parser (L, elt, &up->parser_from_ref,
				&up->parser_to_ref, err)) {
			goto err;
		}

		rspamd_lua_add_ref_dtor (L, pool, up->parser_from_ref);
		rspamd_lua_add_ref_dtor (L, pool, up->parser_to_ref);
	}

	g_hash_table_insert (ctx->upstreams, up->name, up);

	return TRUE;

err:
	return FALSE;
}

static gboolean
rspamd_proxy_parse_mirror (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	const ucl_object_t *elt;
	struct rspamd_http_mirror *up = NULL;
	struct rspamd_proxy_ctx *ctx;
	struct rspamd_rcl_struct_parser *pd = ud;
	lua_State *L;

	ctx = pd->user_struct;
	L = ctx->lua_state;

	if (ucl_object_type (obj) != UCL_OBJECT) {
		g_set_error (err, rspamd_proxy_quark (), 100,
				"mirror option must be an object");

		return FALSE;
	}

	up = rspamd_mempool_alloc0 (pool, sizeof (*up));

	elt = ucl_object_lookup (obj, "name");
	if (elt == NULL) {

		if (ucl_object_key (obj)) {
			if (strcmp (ucl_object_key (obj), "mirror") == 0) {
				/* Iterate over the object and find upstream elements */
				ucl_object_iter_t it = NULL;
				const ucl_object_t *cur;
				gboolean ret = TRUE;

				while ((cur = ucl_object_iterate (obj, &it, true)) != NULL) {
					if (!rspamd_proxy_parse_mirror (pool, cur, ud,
							section, err)) {
						ret = FALSE;
					}
				}

				return ret;
			}
			else {
				/* Inside upstream */
				up->name = rspamd_mempool_strdup (pool, ucl_object_key (obj));
			}
		}
		else {
			g_set_error (err, rspamd_proxy_quark (), 100,
					"mirror option must have some name definition");

			return FALSE;
		}
	}
	else {
		up->name = rspamd_mempool_strdup (pool, ucl_object_tostring (elt));
	}

	up->parser_to_ref = -1;
	up->parser_from_ref = -1;
	up->timeout = ctx->timeout;

	elt = ucl_object_lookup (obj, "key");
	if (elt != NULL) {
		up->key = rspamd_pubkey_from_base32 (ucl_object_tostring (elt), 0,
				RSPAMD_KEYPAIR_KEX, RSPAMD_CRYPTOBOX_MODE_25519);

		if (up->key == NULL) {
			g_set_error (err, rspamd_proxy_quark (), 100,
					"cannot read mirror key");

			goto err;
		}

		rspamd_mempool_add_destructor (pool,
				(rspamd_mempool_destruct_t)rspamd_pubkey_unref, up->key);
	}

	elt = ucl_object_lookup (obj, "hosts");

	if (elt == NULL) {
		g_set_error (err, rspamd_proxy_quark (), 100,
				"mirror option must have some hosts definition");

		goto err;
	}

	up->u = rspamd_upstreams_create (ctx->cfg->ups_ctx);
	if (!rspamd_upstreams_from_ucl (up->u, elt, 11333, NULL)) {
		g_set_error (err, rspamd_proxy_quark (), 100,
				"mirror has bad hosts definition");

		goto err;
	}

	rspamd_mempool_add_destructor (pool,
			(rspamd_mempool_destruct_t)rspamd_upstreams_destroy, up->u);

	elt = ucl_object_lookup_any (obj, "probability", "prob", NULL);
	if (elt) {
		up->prob = ucl_object_todouble (elt);
	}
	else {
		up->prob = 1.0;
	}

	elt = ucl_object_lookup (obj, "local");
	if (elt && ucl_object_toboolean (elt)) {
		up->local = TRUE;
	}

	elt = ucl_object_lookup_any (obj, "compress", "compression", NULL);
	if (elt && ucl_object_toboolean (elt)) {
		up->compress = TRUE;
	}

	elt = ucl_object_lookup (obj, "timeout");
	if (elt) {
		ucl_object_todouble_safe (elt, &up->timeout);
	}

	/*
	 * Accept lua function here in form
	 * fun :: String -> UCL
	 */
	elt = ucl_object_lookup (obj, "parser");
	if (elt) {
		if (!rspamd_proxy_parse_lua_parser (L, elt, &up->parser_from_ref,
				&up->parser_to_ref, err)) {
			goto err;
		}

		rspamd_lua_add_ref_dtor (L, pool, up->parser_from_ref);
		rspamd_lua_add_ref_dtor (L, pool, up->parser_to_ref);
	}

	elt = ucl_object_lookup_any (obj, "settings", "settings_id", NULL);
	if (elt && ucl_object_type (elt) == UCL_STRING) {
		up->settings_id = rspamd_mempool_strdup (pool, ucl_object_tostring (elt));
	}

	g_ptr_array_add (ctx->mirrors, up);

	return TRUE;

err:

	return FALSE;
}

static gboolean
rspamd_proxy_parse_script (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	struct rspamd_proxy_ctx *ctx;
	struct rspamd_rcl_struct_parser *pd = ud;
	lua_State *L;
	const gchar *lua_script;
	gsize slen;
	gint err_idx, ref_idx;
	struct stat st;

	ctx = pd->user_struct;
	L = ctx->lua_state;

	if (ucl_object_type (obj) != UCL_STRING) {
		g_set_error (err, rspamd_proxy_quark (), 100,
				"script option must be a string with file or lua chunk");

		return FALSE;
	}

	lua_script = ucl_object_tolstring (obj, &slen);
	lua_pushcfunction (L, &rspamd_lua_traceback);
	err_idx = lua_gettop (L);

	if (stat (lua_script, &st) != -1) {
		/* Load file */
		if (luaL_loadfile (L, lua_script) != 0) {
			g_set_error (err,
					rspamd_proxy_quark (),
					EINVAL,
					"cannot load lua parser script: %s",
					lua_tostring (L, -1));
			lua_settop (L, 0); /* Error function */

			goto err;
		}
	}
	else {
		/* Load data directly */
		if (luaL_loadbuffer (L, lua_script, slen, "proxy parser") != 0) {
			g_set_error (err,
					rspamd_proxy_quark (),
					EINVAL,
					"cannot load lua parser script: %s",
					lua_tostring (L, -1));
			lua_settop (L, 0); /* Error function */

			goto err;
		}
	}

	/* Now do it */
	if (lua_pcall (L, 0, 1, err_idx) != 0) {
		g_set_error (err,
				rspamd_proxy_quark (),
				EINVAL,
				"cannot init lua parser script: %s",
				lua_tostring (L, -1));
		lua_settop (L, 0);

		goto err;
	}

	if (!lua_isfunction (L, -1)) {
		g_set_error (err,
				rspamd_proxy_quark (),
				EINVAL,
				"cannot init lua parser script: "
				"must return function, %s returned",
				lua_typename (L, lua_type (L, -1)));
		lua_settop (L, 0);

		goto err;
	}

	ref_idx = luaL_ref (L, LUA_REGISTRYINDEX);
	lua_settop (L, 0);
	g_array_append_val (ctx->cmp_refs, ref_idx);

	return TRUE;

err:
	return FALSE;
}

gpointer
init_rspamd_proxy (struct rspamd_config *cfg)
{
	struct rspamd_proxy_ctx *ctx;
	GQuark type;

	type = g_quark_try_string ("rspamd_proxy");

	ctx = rspamd_mempool_alloc0 (cfg->cfg_pool,
			sizeof (struct rspamd_proxy_ctx));
	ctx->magic = rspamd_rspamd_proxy_magic;
	ctx->timeout = 120.0;
	ctx->upstreams = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
	rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)g_hash_table_unref, ctx->upstreams);
	ctx->mirrors = g_ptr_array_new ();
	rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)rspamd_ptr_array_free_hard, ctx->mirrors);
	ctx->cfg = cfg;
	ctx->lua_state = cfg->lua_state;
	ctx->cmp_refs = g_array_new (FALSE, FALSE, sizeof (gint));
	rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)rspamd_array_free_hard, ctx->cmp_refs);
	ctx->max_retries = DEFAULT_RETRIES;
	ctx->spam_header = RSPAMD_MILTER_SPAM_HEADER;

	rspamd_rcl_register_worker_option (cfg,
			type,
			"timeout",
			rspamd_rcl_parse_struct_time,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_proxy_ctx, timeout),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			"IO timeout");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"keypair",
			rspamd_rcl_parse_struct_keypair,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_proxy_ctx, key),
			0,
			"Server's keypair");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"upstream",
			rspamd_proxy_parse_upstream,
			ctx,
			0,
			0,
			"List of upstreams");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"mirror",
			rspamd_proxy_parse_mirror,
			ctx,
			0,
			RSPAMD_CL_FLAG_MULTIPLE,
			"List of mirrors");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"script",
			rspamd_proxy_parse_script,
			ctx,
			0,
			RSPAMD_CL_FLAG_MULTIPLE,
			"Compare script to be executed");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"max_retries",
			rspamd_rcl_parse_struct_integer,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_proxy_ctx, max_retries),
			RSPAMD_CL_FLAG_UINT,
			"Maximum number of retries for master connection");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"milter",
			rspamd_rcl_parse_struct_boolean,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_proxy_ctx, milter),
			0,
			"Accept milter connections, not HTTP");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"discard_on_reject",
			rspamd_rcl_parse_struct_boolean,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_proxy_ctx, discard_on_reject),
			0,
			"Tell MTA to discard rejected messages silently");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"quarantine_on_reject",
			rspamd_rcl_parse_struct_boolean,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_proxy_ctx, quarantine_on_reject),
			0,
			"Tell MTA to quarantine rejected messages");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"spam_header",
			rspamd_rcl_parse_struct_string,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_proxy_ctx, spam_header),
			0,
			"Use the specific spam header (default: X-Spam)");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"client_ca_name",
			rspamd_rcl_parse_struct_string,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_proxy_ctx, client_ca_name),
			0,
			"Allow certificates issued by this CA to be treated as client certificates");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"reject_message",
			rspamd_rcl_parse_struct_string,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_proxy_ctx, reject_message),
			0,
			"Use custom rejection message");

	return ctx;
}

static void
proxy_backend_close_connection (struct rspamd_proxy_backend_connection *conn)
{
	if (conn && !(conn->flags & RSPAMD_BACKEND_CLOSED)) {
		if (conn->backend_conn) {
			rspamd_http_connection_reset (conn->backend_conn);
			rspamd_http_connection_unref (conn->backend_conn);
			close (conn->backend_sock);
		}

		conn->flags |= RSPAMD_BACKEND_CLOSED;
	}
}

static gboolean
proxy_backend_parse_results (struct rspamd_proxy_session *session,
							 struct rspamd_proxy_backend_connection *conn,
							 lua_State *L, gint parser_ref,
							 struct rspamd_http_message *msg,
							 goffset *body_offset,
							 const rspamd_ftok_t *ct)
{
	struct ucl_parser *parser;
	gint err_idx;
	const gchar *in = msg->body_buf.begin;
	gsize inlen = msg->body_buf.len;
	const rspamd_ftok_t *offset_hdr;

	if (inlen == 0 || in == NULL) {
		return FALSE;
	}

	offset_hdr = rspamd_http_message_find_header (msg, MESSAGE_OFFSET_HEADER);

	if (offset_hdr) {
		gulong val;

		if (rspamd_strtoul (offset_hdr->begin, offset_hdr->len, &val)
			&& val < inlen) {

			if (body_offset) {
				*body_offset = val;
			}
			inlen = val;
		}
	}

	if (parser_ref != -1) {
		/* Call parser function */
		lua_pushcfunction (L, &rspamd_lua_traceback);
		err_idx = lua_gettop (L);

		lua_rawgeti (L, LUA_REGISTRYINDEX, parser_ref);
		/* XXX: copies all data */
		lua_pushlstring (L, in, inlen);

		if (lua_pcall (L, 1, 1, err_idx) != 0) {
			msg_err_session (
					"cannot run lua parser script: %s",
					lua_tostring (L, -1));
			lua_settop (L, 0);

			return FALSE;
		}

		conn->results = ucl_object_lua_import (L, -1);
		lua_settop (L, 0);
	}
	else {
		rspamd_ftok_t json_ct;
		RSPAMD_FTOK_ASSIGN (&json_ct, "application/json");

		if (ct && rspamd_ftok_casecmp (ct, &json_ct) == 0) {
			parser = ucl_parser_new (0);

			if (!ucl_parser_add_chunk (parser, in, inlen)) {
				gchar *encoded;

				encoded = rspamd_encode_base64 (in, inlen, 0, NULL);
				msg_err_session ("cannot parse input: %s", ucl_parser_get_error (
						parser));
				msg_err_session ("input encoded: %s", encoded);
				ucl_parser_free (parser);
				g_free (encoded);

				return FALSE;
			}

			conn->results = ucl_parser_get_object (parser);
			ucl_parser_free (parser);
		}
	}

	return TRUE;
}

static void
proxy_call_cmp_script (struct rspamd_proxy_session *session, gint cbref)
{
	gint err_idx;
	guint i;
	struct rspamd_proxy_backend_connection *conn;
	lua_State *L;

	L = session->ctx->lua_state;
	lua_pushcfunction (L, &rspamd_lua_traceback);
	err_idx = lua_gettop (L);

	lua_rawgeti (L, LUA_REGISTRYINDEX, cbref);

	lua_createtable (L, 0, session->mirror_conns->len + 1);
	/* Now push master results */
	if (session->master_conn && session->master_conn->results) {
		lua_pushstring (L, "master");
		ucl_object_push_lua (L, session->master_conn->results, true);
		lua_settable (L, -3);
	}
	else {
		lua_pushstring (L, "master");
		lua_pushstring (L, "no results");
		lua_settable (L, -3);
	}

	for (i = 0; i < session->mirror_conns->len; i ++) {
		conn = g_ptr_array_index (session->mirror_conns, i);

		if (conn->results) {
			lua_pushstring (L, conn->name);
			ucl_object_push_lua (L, conn->results, true);
			lua_settable (L, -3);
		}
		else {
			lua_pushstring (L, conn->name);
			lua_pushstring (L, conn->err ? conn->err : "unknown error");
			lua_settable (L, -3);
		}
	}

	if (lua_pcall (L, 1, 0, err_idx) != 0) {
		msg_err_session (
				"cannot run lua compare script: %s",
				lua_tostring (L, -1));
	}

	lua_settop (L, 0);
}

static void
proxy_session_dtor (struct rspamd_proxy_session *session)
{
	guint i;
	gint cbref;
	struct rspamd_proxy_backend_connection *conn;

	if (session->master_conn && session->master_conn->results) {
		for (i = 0; i < session->ctx->cmp_refs->len; i++) {
			cbref = g_array_index (session->ctx->cmp_refs, gint, i);
			proxy_call_cmp_script (session, cbref);
		}
	}

	if (session->master_conn) {
		proxy_backend_close_connection (session->master_conn);
	}

	if (session->client_milter_conn) {
		rspamd_milter_session_unref (session->client_milter_conn);
	}
	else if (session->client_conn) {
		rspamd_http_connection_reset (session->client_conn);
		rspamd_http_connection_unref (session->client_conn);
	}

	if (session->map && session->map_len) {
		munmap (session->map, session->map_len);
	}

	for (i = 0; i < session->mirror_conns->len; i ++) {
		conn = g_ptr_array_index (session->mirror_conns, i);

		if (!(conn->flags & RSPAMD_BACKEND_CLOSED)) {
			proxy_backend_close_connection (conn);
		}

		if (conn->results) {
			ucl_object_unref (conn->results);
		}
	}

	if (session->master_conn) {
		if (session->master_conn->results) {
			ucl_object_unref (session->master_conn->results);
		}

		if (session->master_conn->task) {
			rspamd_session_destroy (session->master_conn->task->s);
		}
	}

	g_ptr_array_free (session->mirror_conns, TRUE);
	rspamd_http_message_shmem_unref (session->shmem_ref);
	rspamd_http_message_unref (session->client_message);

	if (session->client_addr) {
		rspamd_inet_address_free (session->client_addr);
	}

	if (session->client_sock != -1) {
		close (session->client_sock);
	}

	if (session->ctx->sessions_cache) {
		rspamd_worker_session_cache_remove (session->ctx->sessions_cache,
				session);
	}

	if (session->pool) {
		rspamd_mempool_delete (session->pool);
	}

	g_free (session);
}

static void
proxy_request_compress (struct rspamd_http_message *msg)
{
	guint flags;
	ZSTD_CCtx *zctx;
	rspamd_fstring_t *body;
	const gchar *in;
	gsize inlen;

	flags = rspamd_http_message_get_flags (msg);

	if (!rspamd_http_message_find_header (msg, COMPRESSION_HEADER)) {
		if ((flags & RSPAMD_HTTP_FLAG_SHMEM) ||
				!(flags & RSPAMD_HTTP_FLAG_HAS_BODY)) {
			/* Cannot compress shared or empty message */
			return;
		}

		in = rspamd_http_message_get_body (msg, &inlen);

		if (in == NULL || inlen == 0) {
			return;
		}

		body = rspamd_fstring_sized_new (ZSTD_compressBound (inlen));
		zctx = ZSTD_createCCtx ();
		body->len = ZSTD_compressCCtx (zctx, body->str, body->allocated,
				in, inlen, 1);

		if (ZSTD_isError (body->len)) {
			msg_err ("compression error");
			rspamd_fstring_free (body);
			ZSTD_freeCCtx (zctx);

			return;
		}

		ZSTD_freeCCtx (zctx);
		rspamd_http_message_set_body_from_fstring_steal (msg, body);
		rspamd_http_message_add_header (msg, COMPRESSION_HEADER, "zstd");
	}
}

static void
proxy_request_decompress (struct rspamd_http_message *msg)
{
	rspamd_fstring_t *body;
	const gchar *in;
	gsize inlen, outlen, r;
	ZSTD_DStream *zstream;
	ZSTD_inBuffer zin;
	ZSTD_outBuffer zout;

	if (rspamd_http_message_find_header (msg, COMPRESSION_HEADER)) {
		in = rspamd_http_message_get_body (msg, &inlen);

		if (in == NULL || inlen == 0) {
			return;
		}

		zstream = ZSTD_createDStream ();
		ZSTD_initDStream (zstream);

		zin.pos = 0;
		zin.src = in;
		zin.size = inlen;

		if ((outlen = ZSTD_getDecompressedSize (zin.src, zin.size)) == 0) {
			outlen = ZSTD_DStreamOutSize ();
		}

		body = rspamd_fstring_sized_new (outlen);
		zout.dst = body->str;
		zout.pos = 0;
		zout.size = outlen;

		while (zin.pos < zin.size) {
			r = ZSTD_decompressStream (zstream, &zout, &zin);

			if (ZSTD_isError (r)) {
				msg_err ("Decompression error: %s", ZSTD_getErrorName (r));
				ZSTD_freeDStream (zstream);
				rspamd_fstring_free (body);

				return;
			}

			if (zout.pos == zout.size) {
				/* We need to extend output buffer */
				zout.size = zout.size * 2 + 1;
				body = rspamd_fstring_grow (body, zout.size);
				zout.size = body->allocated;
				zout.dst = body->str;
			}
		}

		body->len = zout.pos;
		ZSTD_freeDStream (zstream);
		rspamd_http_message_set_body_from_fstring_steal (msg, body);
		rspamd_http_message_remove_header (msg, COMPRESSION_HEADER);
	}
}

static struct rspamd_proxy_session *
proxy_session_refresh (struct rspamd_proxy_session *session)
{
	struct rspamd_proxy_session *nsession;

	nsession = g_malloc0 (sizeof (*nsession));
	nsession->client_milter_conn = session->client_milter_conn;
	session->client_milter_conn = NULL;
	rspamd_milter_update_userdata (nsession->client_milter_conn,
			nsession);
	nsession->client_addr = session->client_addr;
	session->client_addr = NULL;
	nsession->ctx = session->ctx;
	nsession->worker = session->worker;
	nsession->pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), "proxy", 0);
	nsession->client_sock = session->client_sock;
	session->client_sock = -1;
	nsession->mirror_conns = g_ptr_array_sized_new (nsession->ctx->mirrors->len);

	REF_INIT_RETAIN (nsession, proxy_session_dtor);

	if (nsession->ctx->sessions_cache) {
		rspamd_worker_session_cache_add (nsession->ctx->sessions_cache,
				nsession->pool->tag.uid, &nsession->ref.refcount, nsession);
	}

	return nsession;
}

static gboolean
proxy_check_file (struct rspamd_http_message *msg,
		struct rspamd_proxy_session *session)
{
	const rspamd_ftok_t *tok, *key_tok;
	rspamd_ftok_t srch;
	gchar *file_str;
	GHashTable *query_args;
	GHashTableIter it;
	gpointer k, v;
	struct http_parser_url u;
	rspamd_fstring_t *new_url;

	tok = rspamd_http_message_find_header (msg, "File");

	if (tok) {
		file_str = rspamd_mempool_ftokdup (session->pool, tok);
		session->map = rspamd_file_xmap (file_str, PROT_READ, &session->map_len,
				TRUE);

		if (session->map == NULL) {
			if (session->map_len != 0) {
				msg_err_session ("cannot map %s: %s", file_str,
						strerror (errno));

				return FALSE;
			}
		}
		/* Remove header after processing */
		rspamd_http_message_remove_header (msg, "File");
		session->fname = file_str;
	}
	else {
		/* Need to parse query URL */
		if (http_parser_parse_url (RSPAMD_FSTRING_DATA (msg->url),
				RSPAMD_FSTRING_LEN (msg->url), 0, &u) != 0) {
			msg_err_session ("bad request url: %V", msg->url);

			return FALSE;
		}

		if (u.field_set & (1 << UF_QUERY)) {
			/* In case if we have a query, we need to store it somewhere */
			query_args = rspamd_http_message_parse_query (msg);
			srch.begin = "File";
			srch.len = strlen ("File");
			tok = g_hash_table_lookup (query_args, &srch);

			if (tok) {
				file_str = rspamd_mempool_ftokdup (session->pool, tok);
				session->map = rspamd_file_xmap (file_str, PROT_READ,
						&session->map_len, TRUE);

				if (session->map == NULL) {
					if (session->map_len != 0) {
						msg_err_session ("cannot map %s: %s", file_str,
								strerror (errno));
						g_hash_table_unref (query_args);

						return FALSE;
					}
				}

				/* We need to create a new URL with file attribute removed */
				new_url = rspamd_fstring_new_init (RSPAMD_FSTRING_DATA (msg->url),
						u.field_data[UF_QUERY].off);
				new_url = rspamd_fstring_append (new_url, "?", 1);

				g_hash_table_iter_init (&it, query_args);

				while (g_hash_table_iter_next (&it, &k, &v)) {
					key_tok = k;
					tok = v;

					if (!rspamd_ftok_icase_equal (key_tok, &srch)) {
						rspamd_printf_fstring (&new_url, "%T=%T&",
								key_tok, tok);
					}
				}

				/* Erase last character (might be either & or ?) */
				rspamd_fstring_erase (new_url, new_url->len - 1, 1);

				rspamd_fstring_free (msg->url);
				msg->url = new_url;
				session->fname = file_str;
			}

			g_hash_table_unref (query_args);
		}

	}

	return TRUE;
}

static void
proxy_backend_mirror_error_handler (struct rspamd_http_connection *conn, GError *err)
{
	struct rspamd_proxy_backend_connection *bk_conn = conn->ud;
	struct rspamd_proxy_session *session;

	session = bk_conn->s;
	msg_info_session ("abnormally closing connection from backend: %s:%s, "
			"error: %e",
			bk_conn->name,
			rspamd_inet_address_to_string_pretty (
					rspamd_upstream_addr_cur (bk_conn->up)),
			err);

	if (err) {
		bk_conn->err = rspamd_mempool_strdup (session->pool, err->message);
	}

	rspamd_upstream_fail (bk_conn->up, FALSE, err ? err->message : "unknown");

	proxy_backend_close_connection (bk_conn);
	REF_RELEASE (bk_conn->s);
}

static gint
proxy_backend_mirror_finish_handler (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg)
{
	struct rspamd_proxy_backend_connection *bk_conn = conn->ud;
	struct rspamd_proxy_session *session;
	const rspamd_ftok_t *orig_ct;

	session = bk_conn->s;

	proxy_request_decompress (msg);
	orig_ct = rspamd_http_message_find_header (msg, "Content-Type");

	if (!proxy_backend_parse_results (session, bk_conn, session->ctx->lua_state,
			bk_conn->parser_from_ref, msg, NULL, orig_ct)) {
		msg_warn_session ("cannot parse results from the mirror backend %s:%s",
				bk_conn->name,
				rspamd_inet_address_to_string (
						rspamd_upstream_addr_cur (bk_conn->up)));
		bk_conn->err = "cannot parse ucl";
	}

	msg_info_session ("finished mirror connection to %s", bk_conn->name);
	rspamd_upstream_ok (bk_conn->up);

	proxy_backend_close_connection (bk_conn);
	REF_RELEASE (bk_conn->s);

	return 0;
}

static void
proxy_open_mirror_connections (struct rspamd_proxy_session *session)
{
	gdouble coin;
	struct rspamd_http_mirror *m;
	guint i;
	struct rspamd_proxy_backend_connection *bk_conn;
	struct rspamd_http_message *msg;
	GError *err = NULL;

	coin = rspamd_random_double ();

	for (i = 0; i < session->ctx->mirrors->len; i ++) {
		m = g_ptr_array_index (session->ctx->mirrors, i);

		if (m->prob < coin) {
			/* No luck */
			continue;
		}

		bk_conn = rspamd_mempool_alloc0 (session->pool,
				sizeof (*bk_conn));
		bk_conn->s = session;
		bk_conn->name = m->name;
		bk_conn->timeout = m->timeout;

		bk_conn->up = rspamd_upstream_get (m->u,
				RSPAMD_UPSTREAM_ROUND_ROBIN, NULL, 0);
		bk_conn->parser_from_ref = m->parser_from_ref;
		bk_conn->parser_to_ref = m->parser_to_ref;

		if (bk_conn->up == NULL) {
			msg_err_session ("cannot select upstream for %s", m->name);
			continue;
		}

		bk_conn->backend_sock = rspamd_inet_address_connect (
				rspamd_upstream_addr_next (bk_conn->up),
				SOCK_STREAM, TRUE);

		if (bk_conn->backend_sock == -1) {
			msg_err_session ("cannot connect upstream for %s", m->name);
			rspamd_upstream_fail (bk_conn->up, TRUE, strerror (errno));
			continue;
		}

		msg = rspamd_http_connection_copy_msg (session->client_message, &err);

		if (msg == NULL) {
			msg_err_session ("cannot copy message to send to a mirror %s: %e",
					m->name, err);
			if (err) {
				g_error_free (err);
			}
			continue;
		}

		if (msg->url->len == 0) {
			msg->url = rspamd_fstring_append (msg->url, "/check", strlen ("/check"));
		}

		if (m->settings_id != NULL) {
			rspamd_http_message_remove_header (msg, "Settings-ID");
			rspamd_http_message_add_header (msg, "Settings-ID", m->settings_id);
		}

		bk_conn->backend_conn = rspamd_http_connection_new_client_socket (
				session->ctx->http_ctx,
				NULL,
				proxy_backend_mirror_error_handler,
				proxy_backend_mirror_finish_handler,
				RSPAMD_HTTP_CLIENT_SIMPLE,
				bk_conn->backend_sock);

		if (m->key) {
			msg->peer_key = rspamd_pubkey_ref (m->key);
		}

		if (m->local ||
				rspamd_inet_address_is_local (rspamd_upstream_addr_cur (bk_conn->up))) {

			if (session->fname) {
				rspamd_http_message_add_header (msg, "File", session->fname);
			}

			msg->method = HTTP_GET;
			rspamd_http_connection_write_message_shared (bk_conn->backend_conn,
					msg, NULL, NULL, bk_conn,
					bk_conn->timeout);
		}
		else {
			if (session->fname) {
				msg->flags &= ~RSPAMD_HTTP_FLAG_SHMEM;
				rspamd_http_message_set_body (msg, session->map, session->map_len);
			}

			msg->method = HTTP_POST;

			if (m->compress) {
				proxy_request_compress (msg);

				if (session->client_milter_conn) {
					rspamd_http_message_add_header (msg, "Content-Type",
							"application/octet-stream");
				}
			}
			else {
				if (session->client_milter_conn) {
					rspamd_http_message_add_header (msg, "Content-Type",
							"text/plain");
				}
			}

			rspamd_http_connection_write_message (bk_conn->backend_conn,
					msg, NULL, NULL, bk_conn,
					bk_conn->timeout);
		}

		g_ptr_array_add (session->mirror_conns, bk_conn);
		REF_RETAIN (session);
		msg_info_session ("send request to %s", m->name);
	}
}

static void
proxy_client_write_error (struct rspamd_proxy_session *session, gint code,
		const gchar *status)
{
	struct rspamd_http_message *reply;

	if (session->client_milter_conn) {
		rspamd_milter_send_action (session->client_milter_conn,
				RSPAMD_MILTER_TEMPFAIL);
		REF_RELEASE (session);
	}
	else {
		reply = rspamd_http_new_message (HTTP_RESPONSE);

		switch (code) {
		case ETIMEDOUT:
			reply->code = 504;
			reply->status = RSPAMD_FSTRING_LIT ("Gateway timeout");
			break;
		case ECONNRESET:
		case ECONNABORTED:
			reply->code = 502;
			reply->status = RSPAMD_FSTRING_LIT ("Gateway connection reset");
			break;
		case ECONNREFUSED:
			reply->code = 502;
			reply->status = RSPAMD_FSTRING_LIT ("Gateway connection refused");
			break;
		default:
			if (code >= 300) {
				/* Likely HTTP error */
				reply->code = code;
				reply->status = rspamd_fstring_new_init (status, strlen (status));
			}
			else {
				reply->code = 502;
				reply->status = RSPAMD_FSTRING_LIT ("Unknown gateway error: ");
				reply->status = rspamd_fstring_append (reply->status,
						status, strlen (status));
			}
			break;
		}

		rspamd_http_connection_write_message (session->client_conn,
				reply, NULL, NULL, session,
				session->ctx->timeout);
	}
}

static void
proxy_backend_master_error_handler (struct rspamd_http_connection *conn, GError *err)
{
	struct rspamd_proxy_backend_connection *bk_conn = conn->ud;
	struct rspamd_proxy_session *session;

	session = bk_conn->s;
	session->retries ++;
	msg_info_session ("abnormally closing connection from backend: %s, error: %e,"
					  " retries left: %d",
			rspamd_inet_address_to_string_pretty (
					rspamd_upstream_addr_cur (session->master_conn->up)),
			err,
			session->ctx->max_retries - session->retries);
	rspamd_upstream_fail (bk_conn->up, FALSE, err ? err->message : "unknown");
	proxy_backend_close_connection (session->master_conn);

	if (session->ctx->max_retries > 0 &&
			session->retries >= session->ctx->max_retries) {
		msg_err_session ("cannot connect to upstream, maximum retries "
				"has been reached: %d", session->retries);
		/* Terminate session immediately */
		if (err) {
			proxy_client_write_error(session, err->code, err->message);
		}
		else {
			proxy_client_write_error(session, 503, "Unknown error after no retries left");
		}
	}
	else {
		if (!proxy_send_master_message (session)) {
			if (err) {
				proxy_client_write_error(session, err->code, err->message);
			}
			else {
				proxy_client_write_error(session, 503, "Unknown error on write");
			}
		}
		else {
			msg_info_session ("retry connection to: %s"
					" retries left: %d",
					rspamd_inet_address_to_string (
							rspamd_upstream_addr_cur (session->master_conn->up)),
					session->ctx->max_retries - session->retries);
		}
	}
}

static gint
proxy_backend_master_finish_handler (struct rspamd_http_connection *conn,
									 struct rspamd_http_message *msg)
{
	struct rspamd_proxy_backend_connection *bk_conn = conn->ud;
	struct rspamd_proxy_session *session, *nsession;
	rspamd_fstring_t *reply;
	const rspamd_ftok_t *orig_ct;
	goffset body_offset = -1;

	session = bk_conn->s;
	rspamd_http_connection_steal_msg (session->master_conn->backend_conn);
	proxy_request_decompress (msg);

	/*
	 * These are likely set by an http library, so we will double these headers
	 * if they are not removed
	 */
	rspamd_http_message_remove_header (msg, "Content-Length");
	rspamd_http_message_remove_header (msg, "Connection");
	rspamd_http_message_remove_header (msg, "Date");
	rspamd_http_message_remove_header (msg, "Server");
	rspamd_http_message_remove_header (msg, "Key");
	orig_ct = rspamd_http_message_find_header (msg, "Content-Type");
	rspamd_http_connection_reset (session->master_conn->backend_conn);

	if (!proxy_backend_parse_results (session, bk_conn, session->ctx->lua_state,
			bk_conn->parser_from_ref, msg, &body_offset, orig_ct)) {
		msg_warn_session ("cannot parse results from the master backend");
	}


	if (session->legacy_support > LEGACY_SUPPORT_NO) {
		/* We need to reformat ucl to fit with legacy spamc protocol */
		if (bk_conn->results) {
			reply = rspamd_fstring_new ();

			if (session->legacy_support == LEGACY_SUPPORT_SPAMC) {
				rspamd_ucl_tospamc_output (bk_conn->results, &reply);
				msg->flags |= RSPAMD_HTTP_FLAG_SPAMC;
			}
			else {
				rspamd_ucl_torspamc_output (bk_conn->results, &reply);
			}

			rspamd_http_message_set_body_from_fstring_steal (msg, reply);
			msg->method = HTTP_SYMBOLS;
		}
		else {
			msg_warn_session ("cannot parse results from the master backend, "
					"return them as is");
		}
	}

	rspamd_upstream_ok (bk_conn->up);

	if (session->client_milter_conn) {
		nsession = proxy_session_refresh (session);

		if (body_offset > 0) {
			rspamd_milter_send_task_results (nsession->client_milter_conn,
					session->master_conn->results,
					msg->body_buf.begin + body_offset,
					msg->body_buf.len - body_offset);
		}
		else {
			rspamd_milter_send_task_results (nsession->client_milter_conn,
					session->master_conn->results, NULL, 0);
		}
		REF_RELEASE (session);
		rspamd_http_message_free (msg);
	}
	else {
		const gchar *passed_ct = NULL;

		if (orig_ct) {
			passed_ct = rspamd_mempool_ftokdup (session->pool, orig_ct);
			/* Remove original */
			rspamd_http_message_remove_header (msg, "Content-Type");
		}

		rspamd_http_connection_write_message (session->client_conn,
				msg, NULL, passed_ct, session,
				bk_conn->timeout);
	}

	return 0;
}

static void
rspamd_proxy_scan_self_reply (struct rspamd_task *task)
{
	struct rspamd_http_message *msg;
	struct rspamd_proxy_session *session = task->fin_arg, *nsession;
	ucl_object_t *rep = NULL;
	const char *ctype = "application/json";

	msg = rspamd_http_new_message (HTTP_RESPONSE);
	msg->date = time (NULL);
	msg->code = 200;

	switch (task->cmd) {
	case CMD_CHECK:
	case CMD_SKIP:
	case CMD_CHECK_RSPAMC:
	case CMD_CHECK_SPAMC:
	case CMD_CHECK_V2:
		rspamd_task_set_finish_time (task);
		rspamd_protocol_http_reply (msg, task, &rep);
		rspamd_protocol_write_log_pipe (task);
		break;
	case CMD_PING:
		rspamd_http_message_set_body (msg, "pong" CRLF, 6);
		ctype = "text/plain";
		break;
	default:
		msg_err_task ("BROKEN");
		break;
	}

	session->master_conn->flags |= RSPAMD_BACKEND_CLOSED;

	if (rep) {
		session->master_conn->results = ucl_object_ref (rep);
	}

	if (session->client_milter_conn) {
		nsession = proxy_session_refresh (session);

		if (task->flags & RSPAMD_TASK_FLAG_MESSAGE_REWRITE) {
			const gchar *start;
			goffset len, hdr_off;

			start = task->msg.begin;
			len = task->msg.len;

			hdr_off = MESSAGE_FIELD (task, raw_headers_content).len;

			if (hdr_off < len) {
				start += hdr_off;
				len -= hdr_off;

				/* The problem here is that we need not end of headers, we need
				 * start of body.
				 *
				 * Hence, we need to skip one \r\n till there is anything else in
				 * a line.
				 */

				if (*start == '\r' && len > 0) {
					start++;
					len--;
				}

				if (*start == '\n' && len > 0) {
					start++;
					len--;
				}

				rspamd_milter_send_task_results (nsession->client_milter_conn,
						session->master_conn->results, start, len);
			}
			else {
				/* XXX: should never happen! */
				rspamd_milter_send_task_results (nsession->client_milter_conn,
						session->master_conn->results, NULL, 0);
			}
		}
		else {
			rspamd_milter_send_task_results (nsession->client_milter_conn,
					session->master_conn->results, NULL, 0);
		}
		rspamd_http_message_free (msg);
		REF_RELEASE (session);
	}
	else {
		rspamd_http_connection_reset (session->client_conn);
		rspamd_http_connection_write_message (session->client_conn,
				msg,
				NULL,
				ctype,
				session,
				session->ctx->timeout / 10.0);
	}
}

static gboolean
rspamd_proxy_task_fin (void *ud)
{
	struct rspamd_task *task = ud;

	msg_debug_task ("finish task");

	if (RSPAMD_TASK_IS_PROCESSED (task)) {
		rspamd_proxy_scan_self_reply (task);
		return TRUE;
	}

	if (!rspamd_task_process (task, RSPAMD_TASK_PROCESS_ALL)) {
		rspamd_proxy_scan_self_reply (task);
		return TRUE;
	}

	if (RSPAMD_TASK_IS_PROCESSED (task)) {
		rspamd_proxy_scan_self_reply (task);
		return TRUE;
	}

	/* One more iteration */
	return FALSE;
}

static gboolean
rspamd_proxy_self_scan (struct rspamd_proxy_session *session)
{
	struct rspamd_task *task;
	struct rspamd_http_message *msg;
	const gchar *data;
	gsize len;

	msg = session->client_message;
	task = rspamd_task_new (session->worker, session->ctx->cfg,
			session->pool, session->ctx->lang_det,
			session->ctx->event_loop, FALSE);
	task->flags |= RSPAMD_TASK_FLAG_MIME;

	if (session->ctx->milter) {
		task->protocol_flags |= RSPAMD_TASK_PROTOCOL_FLAG_MILTER|
				RSPAMD_TASK_PROTOCOL_FLAG_BODY_BLOCK;
	}

	task->sock = -1;

	if (session->client_milter_conn) {
		task->client_addr = rspamd_inet_address_copy (
				session->client_milter_conn->addr);
	}
	else {
		task->client_addr = rspamd_inet_address_copy (session->client_addr);
	}

	task->fin_arg = session;
	task->resolver = session->ctx->resolver;
	/* TODO: allow to disable autolearn in protocol */
	task->flags |= RSPAMD_TASK_FLAG_LEARN_AUTO;
	task->s = rspamd_session_create (task->task_pool, rspamd_proxy_task_fin,
			NULL, (event_finalizer_t )rspamd_task_free, task);
	data = rspamd_http_message_get_body (msg, &len);

	if (session->backend->settings_id) {
		rspamd_http_message_remove_header (msg, "Settings-ID");
		rspamd_http_message_add_header (msg, "Settings-ID",
				session->backend->settings_id);
	}

	/* Process message */
	if (!rspamd_protocol_handle_request (task, msg)) {
		msg_err_task ("cannot handle request: %e", task->err);
		task->flags |= RSPAMD_TASK_FLAG_SKIP;
	}
	else {
		if (task->cmd == CMD_PING) {
			task->flags |= RSPAMD_TASK_FLAG_SKIP;
		}
		else {
			if (!rspamd_task_load_message (task, msg, data, len)) {
				msg_err_task ("cannot load message: %e", task->err);
				task->flags |= RSPAMD_TASK_FLAG_SKIP;
			}
		}
	}

	/* Set global timeout for the task */
	if (session->ctx->default_upstream->timeout > 0.0) {
		task->timeout_ev.data = task;
		ev_timer_init (&task->timeout_ev, rspamd_task_timeout,
				session->ctx->default_upstream->timeout,
				session->ctx->default_upstream->timeout);
		ev_timer_start (task->event_loop, &task->timeout_ev);

	}
	else if (session->ctx->has_self_scan) {
		if (session->ctx->cfg->task_timeout > 0) {
			task->timeout_ev.data = task;
			ev_timer_init (&task->timeout_ev, rspamd_task_timeout,
					session->ctx->cfg->task_timeout,
					session->ctx->default_upstream->timeout);
			ev_timer_start (task->event_loop, &task->timeout_ev);
		}
	}

	session->master_conn->task = task;
	rspamd_task_process (task, RSPAMD_TASK_PROCESS_ALL);

	rspamd_session_pending (task->s);

	return TRUE;
}

static gboolean
proxy_send_master_message (struct rspamd_proxy_session *session)
{
	struct rspamd_http_message *msg;
	struct rspamd_http_upstream *backend = NULL;
	const rspamd_ftok_t *host;
	GError *err = NULL;
	gchar hostbuf[512];

	host = rspamd_http_message_find_header (session->client_message, "Host");

	if (host == NULL) {
		backend = session->ctx->default_upstream;
	}
	else {
		rspamd_strlcpy (hostbuf, host->begin, MIN(host->len + 1, sizeof (hostbuf)));
		backend = g_hash_table_lookup (session->ctx->upstreams, hostbuf);

		if (backend == NULL) {
			backend = session->ctx->default_upstream;
		}
	}

	if (backend == NULL) {
		/* No backend */
		msg_err_session ("cannot find upstream for %s", host ? hostbuf : "default");
		goto err;
	}
	else {
		session->backend = backend;

		if (backend->self_scan) {
			return rspamd_proxy_self_scan (session);
		}
retry:
		if (session->ctx->max_retries &&
				session->retries > session->ctx->max_retries) {
			msg_err_session ("cannot connect to upstream, maximum retries "
					"has been reached: %d", session->retries);
			goto err;
		}

		/* Provide hash key if hashing based on source address is desired */
		guint hash_len;
		gpointer hash_key = rspamd_inet_address_get_hash_key (session->client_addr,
				&hash_len);

		if (session->ctx->max_retries > 1 &&
			session->retries == session->ctx->max_retries) {

			session->master_conn->up = rspamd_upstream_get_except (backend->u,
					session->master_conn->up,
					RSPAMD_UPSTREAM_ROUND_ROBIN,
					hash_key, hash_len);
		}
		else {
			session->master_conn->up = rspamd_upstream_get (backend->u,
					RSPAMD_UPSTREAM_ROUND_ROBIN,
					hash_key, hash_len);
		}

		session->master_conn->timeout = backend->timeout;

		if (session->master_conn->up == NULL) {
			msg_err_session ("cannot select upstream for %s",
					host ? hostbuf : "default");
			goto err;
		}

		session->master_conn->backend_sock = rspamd_inet_address_connect (
				rspamd_upstream_addr_next (session->master_conn->up),
				SOCK_STREAM, TRUE);

		if (session->master_conn->backend_sock == -1) {
			msg_err_session ("cannot connect upstream: %s(%s)",
					host ? hostbuf : "default",
							rspamd_inet_address_to_string_pretty (
									rspamd_upstream_addr_cur (
											session->master_conn->up)));
			rspamd_upstream_fail (session->master_conn->up, TRUE,
					strerror (errno));
			session->retries ++;
			goto retry;
		}

		msg = rspamd_http_connection_copy_msg (session->client_message, &err);
		if (msg == NULL) {
			msg_err_session ("cannot copy message to send it to the upstream: %e",
					err);

			if (err) {
				g_error_free (err);
			}

			goto err; /* No fallback here */
		}

		session->master_conn->backend_conn = rspamd_http_connection_new_client_socket (
				session->ctx->http_ctx,
				NULL,
				proxy_backend_master_error_handler,
				proxy_backend_master_finish_handler,
				RSPAMD_HTTP_CLIENT_SIMPLE,
				session->master_conn->backend_sock);
		session->master_conn->flags &= ~RSPAMD_BACKEND_CLOSED;
		session->master_conn->parser_from_ref = backend->parser_from_ref;
		session->master_conn->parser_to_ref = backend->parser_to_ref;

		if (backend->key) {
			msg->peer_key = rspamd_pubkey_ref (backend->key);
		}

		if (backend->settings_id != NULL) {
			rspamd_http_message_remove_header (msg, "Settings-ID");
			rspamd_http_message_add_header (msg, "Settings-ID",
					backend->settings_id);
		}

		if (backend->local ||
				rspamd_inet_address_is_local (
						rspamd_upstream_addr_cur (
								session->master_conn->up))) {

			if (session->fname) {
				rspamd_http_message_add_header (msg, "File", session->fname);
			}

			msg->method = HTTP_GET;

			rspamd_http_connection_write_message_shared (
					session->master_conn->backend_conn,
					msg, NULL, NULL, session->master_conn,
					session->master_conn->timeout);
		}
		else {
			if (session->fname) {
				msg->flags &= ~RSPAMD_HTTP_FLAG_SHMEM;
				rspamd_http_message_set_body (msg,
						session->map, session->map_len);
			}

			msg->method = HTTP_POST;

			if (backend->compress) {
				proxy_request_compress (msg);
				if (session->client_milter_conn) {
					rspamd_http_message_add_header (msg, "Content-Type",
							"application/octet-stream");
				}
			}
			else {
				if (session->client_milter_conn) {
					rspamd_http_message_add_header (msg, "Content-Type",
							"text/plain");
				}
			}

			rspamd_http_connection_write_message (
					session->master_conn->backend_conn,
					msg, NULL, NULL, session->master_conn,
					session->master_conn->timeout);
		}
	}

	return TRUE;

err:
	if (session->client_milter_conn) {
		rspamd_milter_send_action (session->client_milter_conn,
				RSPAMD_MILTER_TEMPFAIL);
		REF_RELEASE (session);
	}
	else {
		rspamd_http_connection_steal_msg (session->client_conn);
		rspamd_http_connection_reset (session->client_conn);
		proxy_client_write_error (session, 404, "Backend not found");
	}

	return FALSE;
}

static void
proxy_client_error_handler (struct rspamd_http_connection *conn, GError *err)
{
	struct rspamd_proxy_session *session = conn->ud;

	msg_info_session ("abnormally closing connection from: %s, error: %s",
		rspamd_inet_address_to_string (session->client_addr), err->message);
	/* Terminate session immediately */
	proxy_backend_close_connection (session->master_conn);
	REF_RELEASE (session);
}

static gint
proxy_client_finish_handler (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg)
{
	struct rspamd_proxy_session *session = conn->ud;

	if (!session->master_conn) {
		session->master_conn = rspamd_mempool_alloc0 (session->pool,
				sizeof (*session->master_conn));
		session->master_conn->s = session;
		session->master_conn->name = "master";

		/* Reset spamc legacy */
		if (msg->method >= HTTP_SYMBOLS) {
			msg->method = HTTP_POST;

			if (msg->flags & RSPAMD_HTTP_FLAG_SPAMC) {
				session->legacy_support = LEGACY_SUPPORT_SPAMC;
				msg_info_session ("enabling legacy spamc mode for session");
			}
			else {
				session->legacy_support = LEGACY_SUPPORT_RSPAMC;
				msg_info_session ("enabling legacy rspamc mode for session");
			}
		}

		if (msg->url->len == 0) {
			msg->url = rspamd_fstring_append (msg->url,
					"/" MSG_CMD_CHECK_V2, strlen ("/" MSG_CMD_CHECK_V2));
		}

		if (!proxy_check_file (msg, session)) {
			goto err;
		}

		session->client_message = rspamd_http_connection_steal_msg (
				session->client_conn);
		session->shmem_ref = rspamd_http_message_shmem_ref (session->client_message);
		rspamd_http_message_remove_header (msg, "Content-Length");
		rspamd_http_message_remove_header (msg, "Transfer-Encoding");
		rspamd_http_message_remove_header (msg, "Keep-Alive");
		rspamd_http_message_remove_header (msg, "Connection");
		rspamd_http_message_remove_header (msg, "Key");

		proxy_open_mirror_connections (session);
		rspamd_http_connection_reset (session->client_conn);

		proxy_send_master_message (session);
	}
	else {
		msg_info_session ("finished master connection");
		proxy_backend_close_connection (session->master_conn);
		REF_RELEASE (session);
	}

	return 0;

err:
	rspamd_http_connection_steal_msg (session->client_conn);
	rspamd_http_message_remove_header (msg, "Content-Length");
	rspamd_http_message_remove_header (msg, "Key");
	rspamd_http_message_remove_header (msg, "Transfer-Encoding");
	rspamd_http_message_remove_header (msg, "Keep-Alive");
	rspamd_http_message_remove_header (msg, "Connection");
	rspamd_http_connection_reset (session->client_conn);
	proxy_client_write_error (session, 404, "Backend not found");

	return 0;
}

static void
proxy_milter_finish_handler (gint fd,
		struct rspamd_milter_session *rms,
		void *ud)
{
	struct rspamd_proxy_session *session = ud;
	struct rspamd_http_message *msg;

	session->client_milter_conn = rms;

	if (rms->message == NULL || rms->message->len == 0) {
		msg_info_session ("finished milter connection");
		proxy_backend_close_connection (session->master_conn);
		REF_RELEASE (session);
	}
	else {
		if (!session->master_conn) {
			session->master_conn = rspamd_mempool_alloc0 (session->pool,
					sizeof (*session->master_conn));
		}

		msg = rspamd_milter_to_http (rms);
		session->master_conn->s = session;
		session->master_conn->name = "master";
		session->client_message = msg;

		proxy_open_mirror_connections (session);
		proxy_send_master_message (session);
	}
}

static void
proxy_milter_error_handler (gint fd,
		struct rspamd_milter_session *rms, /* unused */
		void *ud, GError *err)
{
	struct rspamd_proxy_session *session = ud;

	if (err && err->code != 0) {
		msg_info_session ("abnormally closing milter connection from: %s, "
						  "error: %e",
				rspamd_inet_address_to_string_pretty (session->client_addr),
				err);
		/* Terminate session immediately */
		proxy_backend_close_connection (session->master_conn);
		REF_RELEASE (session);
	}
	else {
		msg_info_session ("normally closing milter connection from: %s, "
						  "%e",
				rspamd_inet_address_to_string_pretty (session->client_addr),
				err);
		/* Terminate session immediately */
		proxy_backend_close_connection (session->master_conn);
		REF_RELEASE (session);
	}
}

static void
proxy_accept_socket (EV_P_ ev_io *w, int revents)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)w->data;
	struct rspamd_proxy_ctx *ctx;
	rspamd_inet_addr_t *addr = NULL;
	struct rspamd_proxy_session *session;
	gint nfd;

	ctx = worker->ctx;

	if ((nfd =
		rspamd_accept_from_socket (w->fd, &addr,
				rspamd_worker_throttle_accept_events, worker->accept_events)) == -1) {
		msg_warn ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		rspamd_inet_address_free (addr);
		return;
	}

	session = g_malloc0 (sizeof (*session));
	REF_INIT_RETAIN (session, proxy_session_dtor);
	session->client_sock = nfd;
	session->client_addr = addr;
	session->mirror_conns = g_ptr_array_sized_new (ctx->mirrors->len);

	session->pool = rspamd_mempool_new (rspamd_mempool_suggest_size (),
			"proxy", 0);
	session->ctx = ctx;
	session->worker = worker;

	if (ctx->sessions_cache) {
		rspamd_worker_session_cache_add (ctx->sessions_cache,
				session->pool->tag.uid, &session->ref.refcount, session);
	}

	if (!ctx->milter) {
		session->client_conn = rspamd_http_connection_new_server (
				ctx->http_ctx,
				nfd,
				NULL,
				proxy_client_error_handler,
				proxy_client_finish_handler,
				0);

		if (ctx->key) {
			rspamd_http_connection_set_key (session->client_conn, ctx->key);
		}

		msg_info_session ("accepted http connection from %s port %d",
				rspamd_inet_address_to_string (addr),
				rspamd_inet_address_get_port (addr));

		rspamd_http_connection_read_message_shared (session->client_conn,
				session,
				session->ctx->timeout);
	}
	else {
		msg_info_session ("accepted milter connection from %s port %d",
				rspamd_inet_address_to_string (addr),
				rspamd_inet_address_get_port (addr));

#ifdef TCP_NODELAY

	#ifndef SOL_TCP
	#define SOL_TCP IPPROTO_TCP
	#endif

		if (rspamd_inet_address_get_af (addr) != AF_UNIX) {
			gint sopt = 1;

			if (setsockopt (nfd, SOL_TCP, TCP_NODELAY, &sopt, sizeof (sopt)) ==
					-1) {
				msg_warn_session ("cannot set TCP_NODELAY: %s",
						strerror (errno));
			}
		}
#endif

		rspamd_milter_handle_socket (nfd, 0.0,
				session->pool,
				ctx->event_loop,
				proxy_milter_finish_handler,
				proxy_milter_error_handler,
				session);
	}
}

static void
adjust_upstreams_limits (struct rspamd_proxy_ctx *ctx)
{
	struct rspamd_http_upstream *backend;
	gpointer k, v;
	GHashTableIter it;

	/*
	 * We set error time equal to max_retries * backend_timeout and max_errors
	 * to max_retries - 1
	 *
	 * So if we failed to scan a message on a backend for some reasons, we
	 * will try to re-resolve it faster
	 */

	g_hash_table_iter_init (&it, ctx->upstreams);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		backend = (struct rspamd_http_upstream *)v;

		if (!backend->self_scan && backend->u) {
			rspamd_upstreams_set_limits (backend->u,
					NAN, NAN, ctx->max_retries * backend->timeout, NAN,
					ctx->max_retries - 1, 0);
		}
	}
}

__attribute__((noreturn))
void
start_rspamd_proxy (struct rspamd_worker *worker)
{
	struct rspamd_proxy_ctx *ctx = worker->ctx;
	gboolean is_controller = FALSE;

	g_assert (rspamd_worker_check_context (worker->ctx, rspamd_rspamd_proxy_magic));
	ctx->cfg = worker->srv->cfg;
	ctx->event_loop = rspamd_prepare_worker (worker, "rspamd_proxy",
			proxy_accept_socket);

	ctx->resolver = rspamd_dns_resolver_init (worker->srv->logger,
			ctx->event_loop,
			worker->srv->cfg);

	rspamd_upstreams_library_config (worker->srv->cfg, ctx->cfg->ups_ctx,
			ctx->event_loop, ctx->resolver->r);

	ctx->http_ctx = rspamd_http_context_create (ctx->cfg, ctx->event_loop,
			ctx->cfg->ups_ctx);
	rspamd_mempool_add_destructor (ctx->cfg->cfg_pool,
			(rspamd_mempool_destruct_t)rspamd_http_context_free,
			ctx->http_ctx);

	if (ctx->has_self_scan) {
		/* Additional initialisation needed */
		rspamd_worker_init_scanner (worker, ctx->event_loop, ctx->resolver,
				&ctx->lang_det);

		if (worker->index == 0) {
			/*
			 * If there are no controllers and no normal workers,
			 * then pretend that we are a controller
			 */
			gboolean controller_seen = FALSE;
			GList *cur;

			cur = worker->srv->cfg->workers;

			while (cur) {
				struct rspamd_worker_conf *cf;

				cf = (struct rspamd_worker_conf *)cur->data;
				if ((cf->type == g_quark_from_static_string ("controller")) ||
						(cf->type == g_quark_from_static_string ("normal"))) {

					if (cf->enabled && cf->count >= 0) {
						controller_seen = TRUE;
						break;
					}
				}

				cur = g_list_next (cur);
			}

			if (!controller_seen) {
				msg_info ("no controller or normal workers defined, execute "
							  "controller periodics in this worker");
				worker->flags |= RSPAMD_WORKER_CONTROLLER;
				is_controller = TRUE;
			}
		}
	}
	else {
		worker->flags &= ~RSPAMD_WORKER_SCANNER;
	}

	if (worker->srv->cfg->enable_sessions_cache) {
		ctx->sessions_cache = rspamd_worker_session_cache_new (worker,
				ctx->event_loop);
	}

	ctx->milter_ctx.spam_header = ctx->spam_header;
	ctx->milter_ctx.discard_on_reject = ctx->discard_on_reject;
	ctx->milter_ctx.quarantine_on_reject = ctx->quarantine_on_reject;
	ctx->milter_ctx.sessions_cache = ctx->sessions_cache;
	ctx->milter_ctx.client_ca_name = ctx->client_ca_name;
	ctx->milter_ctx.reject_message = ctx->reject_message;
	ctx->milter_ctx.cfg = ctx->cfg;
	rspamd_milter_init_library (&ctx->milter_ctx);

	if (is_controller) {
		rspamd_worker_init_controller (worker, NULL);
	}
	else {
		if (ctx->has_self_scan) {
			rspamd_map_watch (worker->srv->cfg, ctx->event_loop, ctx->resolver,
					worker, RSPAMD_MAP_WATCH_SCANNER);
		}
		else {
			rspamd_map_watch (worker->srv->cfg, ctx->event_loop, ctx->resolver,
					worker, RSPAMD_MAP_WATCH_WORKER);
		}
	}

	rspamd_lua_run_postloads (ctx->cfg->lua_state, ctx->cfg, ctx->event_loop,
			worker);
	adjust_upstreams_limits (ctx);

	ev_loop (ctx->event_loop, 0);
	rspamd_worker_block_signals ();

	if (ctx->has_self_scan) {
		rspamd_stat_close ();
	}

	if (is_controller) {
		rspamd_controller_on_terminate (worker, NULL);
	}

	REF_RELEASE (ctx->cfg);
	rspamd_log_close (worker->srv->logger);

	exit (EXIT_SUCCESS);
}
