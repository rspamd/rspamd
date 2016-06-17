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
#include "libutil/map.h"
#include "libutil/upstream.h"
#include "libutil/http.h"
#include "libutil/http_private.h"
#include "libserver/protocol.h"
#include "libserver/cfg_file.h"
#include "libserver/url.h"
#include "libserver/dns.h"
#include "libmime/message.h"
#include "rspamd.h"
#include "libserver/worker_util.h"
#include "lua/lua_common.h"
#include "keypairs_cache.h"
#include "ottery.h"
#include "unix-std.h"

/* Rotate keys each minute by default */
#define DEFAULT_ROTATION_TIME 60.0

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
#define msg_debug_session(...)  rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
        session->pool->tag.tagname, session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

gpointer init_rspamd_proxy (struct rspamd_config *cfg);
void start_rspamd_proxy (struct rspamd_worker *worker);

worker_t rspamd_proxy_worker = {
	"rspamd_proxy",               /* Name */
	init_rspamd_proxy,            /* Init function */
	start_rspamd_proxy,           /* Start function */
	RSPAMD_WORKER_HAS_SOCKET | RSPAMD_WORKER_KILLABLE,
	RSPAMD_WORKER_SOCKET_TCP,    /* TCP socket */
	RSPAMD_WORKER_VER
};

struct rspamd_http_upstream {
	gchar *name;
	struct upstream_list *u;
	struct rspamd_cryptobox_pubkey *key;
	gdouble timeout;
	struct timeval io_tv;
	gint parser_from_ref;
	gint parser_to_ref;
	gboolean local;
};

struct rspamd_http_mirror {
	gchar *name;
	gchar *settings_id;
	struct upstream_list *u;
	struct rspamd_cryptobox_pubkey *key;
	gdouble prob;
	gdouble timeout;
	struct timeval io_tv;
	gint parser_from_ref;
	gint parser_to_ref;
	gboolean local;
};

static const guint64 rspamd_rspamd_proxy_magic = 0xcdeb4fd1fc351980ULL;

struct rspamd_proxy_ctx {
	guint64 magic;
	gdouble timeout;
	struct timeval io_tv;
	struct rspamd_config *cfg;
	/* DNS resolver */
	struct rspamd_dns_resolver *resolver;
	/* Events base */
	struct event_base *ev_base;
	/* Encryption key for clients */
	struct rspamd_cryptobox_keypair *key;
	/* Keys cache */
	struct rspamd_keypair_cache *keys_cache;
	/* Upstreams to use */
	GHashTable *upstreams;
	/* Mirrors to send traffic to */
	GPtrArray *mirrors;
	/* Default upstream */
	struct rspamd_http_upstream *default_upstream;
	/* Local rotating keypair for upstreams */
	struct rspamd_cryptobox_keypair *local_key;
	struct event rotate_ev;
	gdouble rotate_tm;
	lua_State *lua_state;
	/* Array of callback functions called on end of scan to compare results */
	GArray *cmp_refs;
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
	struct timeval *io_tv;
	gint backend_sock;
	enum rspamd_backend_flags flags;
	gint parser_from_ref;
	gint parser_to_ref;
};

struct rspamd_proxy_session {
	rspamd_mempool_t *pool;
	struct rspamd_proxy_ctx *ctx;
	rspamd_inet_addr_t *client_addr;
	struct rspamd_http_connection *client_conn;
	gpointer map;
	gpointer shmem_ref;
	struct rspamd_proxy_backend_connection *master_conn;
	GPtrArray *mirror_conns;
	gsize map_len;
	gint client_sock;
	gboolean is_spamc;
	ref_entry_t ref;
};

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
	GString *tb = NULL;
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
		tb = lua_touserdata (L, -1);
		g_set_error (err,
				rspamd_proxy_quark (),
				EINVAL,
				"cannot init lua parser script: %s",
				tb->str);
		g_string_free (tb, TRUE);
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

	elt = ucl_object_lookup (obj, "name");
	if (elt == NULL) {
		g_set_error (err, rspamd_proxy_quark (), 100,
				"upstream option must have some name definition");

		return FALSE;
	}

	up = g_slice_alloc0 (sizeof (*up));
	up->parser_from_ref = -1;
	up->parser_to_ref = -1;
	up->name = g_strdup (ucl_object_tostring (elt));
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
	}

	elt = ucl_object_lookup (obj, "hosts");

	if (elt == NULL) {
		g_set_error (err, rspamd_proxy_quark (), 100,
				"upstream option must have some hosts definition");

		goto err;
	}

	up->u = rspamd_upstreams_create (ctx->cfg->ups_ctx);
	if (!rspamd_upstreams_from_ucl (up->u, elt, 11333, NULL)) {
		g_set_error (err, rspamd_proxy_quark (), 100,
				"upstream has bad hosts definition");

		goto err;
	}

	elt = ucl_object_lookup (obj, "default");
	if (elt && ucl_object_toboolean (elt)) {
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
	}

	double_to_tv (up->timeout, &up->io_tv);

	g_hash_table_insert (ctx->upstreams, up->name, up);

	return TRUE;

err:

	if (up) {
		g_free (up->name);
		rspamd_upstreams_destroy (up->u);

		if (up->key) {
			rspamd_pubkey_unref (up->key);
		}

		if (up->parser_from_ref != -1) {
			luaL_unref (L, LUA_REGISTRYINDEX, up->parser_from_ref);
		}
		if (up->parser_to_ref != -1) {
			luaL_unref (L, LUA_REGISTRYINDEX, up->parser_to_ref);
		}

		g_slice_free1 (sizeof (*up), up);
	}

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

	elt = ucl_object_lookup (obj, "name");
	if (elt == NULL) {
		g_set_error (err, rspamd_proxy_quark (), 100,
				"mirror option must have some name definition");

		return FALSE;
	}

	up = g_slice_alloc0 (sizeof (*up));
	up->name = g_strdup (ucl_object_tostring (elt));
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
	}

	elt = ucl_object_lookup_any (obj, "settings", "settings_id", NULL);
	if (elt && ucl_object_type (elt) == UCL_STRING) {
		up->settings_id = g_strdup (ucl_object_tostring (elt));
	}

	double_to_tv (up->timeout, &up->io_tv);

	g_ptr_array_add (ctx->mirrors, up);

	return TRUE;

err:

	if (up) {
		g_free (up->name);
		rspamd_upstreams_destroy (up->u);

		if (up->key) {
			rspamd_pubkey_unref (up->key);
		}

		if (up->parser_from_ref != -1) {
			luaL_unref (L, LUA_REGISTRYINDEX, up->parser_from_ref);
		}
		if (up->parser_to_ref != -1) {
			luaL_unref (L, LUA_REGISTRYINDEX, up->parser_to_ref);
		}

		g_slice_free1 (sizeof (*up), up);
	}

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
	GString *tb = NULL;
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
		tb = lua_touserdata (L, -1);
		g_set_error (err,
				rspamd_proxy_quark (),
				EINVAL,
				"cannot init lua parser script: %s",
				tb->str);
		g_string_free (tb, TRUE);
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

	ctx = g_malloc0 (sizeof (struct rspamd_proxy_ctx));
	ctx->magic = rspamd_rspamd_proxy_magic;
	ctx->timeout = 10.0;
	ctx->upstreams = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
	ctx->mirrors = g_ptr_array_new ();
	ctx->rotate_tm = DEFAULT_ROTATION_TIME;
	ctx->cfg = cfg;
	ctx->lua_state = cfg->lua_state;
	ctx->cmp_refs = g_array_new (FALSE, FALSE, sizeof (gint));

	rspamd_rcl_register_worker_option (cfg,
			type,
			"timeout",
			rspamd_rcl_parse_struct_time,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_proxy_ctx,
					timeout),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			"IO timeout");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"rotate",
			rspamd_rcl_parse_struct_time,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_proxy_ctx,
					rotate_tm),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			"Rotation keys time, default: "
			G_STRINGIFY (DEFAULT_ROTATION_TIME) " seconds");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"keypair",
			rspamd_rcl_parse_struct_keypair,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_proxy_ctx,
					key),
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

	return ctx;
}

static void
proxy_backend_close_connection (struct rspamd_proxy_backend_connection *conn)
{
	if (conn && !(conn->flags & RSPAMD_BACKEND_CLOSED)) {
		if (conn->backend_conn) {
			rspamd_http_connection_reset (conn->backend_conn);
			rspamd_http_connection_unref (conn->backend_conn);
		}

		close (conn->backend_sock);

		conn->flags |= RSPAMD_BACKEND_CLOSED;
	}
}

static gboolean
proxy_backend_parse_results (struct rspamd_proxy_session *session,
		struct rspamd_proxy_backend_connection *conn,
		lua_State *L, gint parser_ref,
		const gchar *in, gsize inlen)
{
	struct ucl_parser *parser;
	GString *tb = NULL;
	gint err_idx;

	if (inlen == 0 || in == NULL) {
		return FALSE;
	}

	if (parser_ref != -1) {
		/* Call parser function */
		lua_pushcfunction (L, &rspamd_lua_traceback);
		err_idx = lua_gettop (L);

		lua_rawgeti (L, LUA_REGISTRYINDEX, parser_ref);
		/* XXX: copies all data */
		lua_pushlstring (L, in, inlen);

		if (lua_pcall (L, 1, 1, err_idx) != 0) {
			tb = lua_touserdata (L, -1);
			msg_err_session (
					"cannot run lua parser script: %s",
					tb->str);
			g_string_free (tb, TRUE);
			lua_settop (L, 0);

			return FALSE;
		}

		conn->results = ucl_object_lua_import (L, -1);
		lua_settop (L, 0);
	}
	else {
		parser = ucl_parser_new (0);

		if (!ucl_parser_add_chunk (parser, in, inlen)) {
			msg_err_session ("cannot parse input: %s", ucl_parser_get_error (
					parser));
			ucl_parser_free (parser);

			return FALSE;
		}

		conn->results = ucl_parser_get_object (parser);
		ucl_parser_free (parser);
	}

	return TRUE;
}

static void
proxy_call_cmp_script (struct rspamd_proxy_session *session, gint cbref)
{
	GString *tb = NULL;
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
		tb = lua_touserdata (L, -1);
		msg_err_session (
				"cannot run lua compare script: %s",
				tb->str);
		g_string_free (tb, TRUE);
	}

	lua_settop (L, 0);
}

static void
proxy_session_dtor (struct rspamd_proxy_session *session)
{
	guint i;
	gint cbref;
	struct rspamd_proxy_backend_connection *conn;

	for (i = 0; i < session->ctx->cmp_refs->len; i ++) {
		cbref = g_array_index (session->ctx->cmp_refs, gint, i);
		proxy_call_cmp_script (session, cbref);
	}

	if (session->master_conn) {
		proxy_backend_close_connection (session->master_conn);
	}

	if (session->map && session->map_len) {
		munmap (session->map, session->map_len);
	}

	if (session->client_conn) {
		rspamd_http_connection_reset (session->client_conn);
		rspamd_http_connection_unref (session->client_conn);
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

	if (session->master_conn && session->master_conn->results) {
		ucl_object_unref (session->master_conn->results);
	}

	g_ptr_array_free (session->mirror_conns, TRUE);
	rspamd_http_message_shmem_unref (session->shmem_ref);
	rspamd_inet_address_destroy (session->client_addr);
	close (session->client_sock);
	rspamd_mempool_delete (session->pool);
	g_slice_free1 (sizeof (*session), session);
}

static gboolean
proxy_check_file (struct rspamd_http_message *msg,
		struct rspamd_proxy_session *session)
{
	const rspamd_ftok_t *tok, *key_tok;
	rspamd_ftok_t srch;
	const gchar *file_str;
	GHashTable *query_args;
	GHashTableIter it;
	gpointer k, v;
	struct http_parser_url u;
	rspamd_fstring_t *new_url;

	tok = rspamd_http_message_find_header (msg, "File");

	if (tok) {
		file_str = rspamd_mempool_ftokdup (session->pool, tok);
		session->map = rspamd_file_xmap (file_str, PROT_READ,
				&session->map_len);

		if (session->map == NULL) {
			msg_err_session ("cannot map %s: %s", file_str, strerror (errno));

			return FALSE;
		}
		/* Remove header after processing */
		rspamd_http_message_remove_header (msg, "File");
	}
	else {
		/* Need to parse query URL */
		if (http_parser_parse_url (msg->url->str, msg->url->len, 0, &u) != 0) {
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
						&session->map_len);

				if (session->map == NULL) {
					msg_err_session ("cannot map %s: %s", file_str, strerror (errno));
					g_hash_table_unref (query_args);

					return FALSE;
				}

				/* We need to create a new URL with file attribute removed */
				new_url = rspamd_fstring_new_init (msg->url->str,
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
			rspamd_inet_address_to_string (rspamd_upstream_addr (bk_conn->up)),
			err);

	if (err) {
		bk_conn->err = rspamd_mempool_strdup (session->pool, err->message);
	}

	proxy_backend_close_connection (bk_conn);
	REF_RELEASE (bk_conn->s);
}

static gint
proxy_backend_mirror_finish_handler (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg)
{
	struct rspamd_proxy_backend_connection *bk_conn = conn->ud;
	struct rspamd_proxy_session *session;

	session = bk_conn->s;

	if (!proxy_backend_parse_results (session, bk_conn, session->ctx->lua_state,
			bk_conn->parser_from_ref, msg->body_buf.begin, msg->body_buf.len)) {
		msg_warn_session ("cannot parse results from the mirror backend %s:%s",
				bk_conn->name,
				rspamd_inet_address_to_string (rspamd_upstream_addr (bk_conn->up)));
		bk_conn->err = "cannot parse ucl";
	}

	msg_info_session ("finished mirror connection to %s", bk_conn->name);

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
		bk_conn->io_tv = &m->io_tv;

		bk_conn->up = rspamd_upstream_get (m->u,
				RSPAMD_UPSTREAM_ROUND_ROBIN, NULL, 0);
		bk_conn->parser_from_ref = m->parser_from_ref;
		bk_conn->parser_to_ref = m->parser_to_ref;

		if (bk_conn->up == NULL) {
			msg_err_session ("cannot select upstream for %s", m->name);
			continue;
		}

		bk_conn->backend_sock = rspamd_inet_address_connect (
				rspamd_upstream_addr (bk_conn->up),
				SOCK_STREAM, TRUE);

		if (bk_conn->backend_sock == -1) {
			msg_err_session ("cannot connect upstream for %s", m->name);
			rspamd_upstream_fail (bk_conn->up);
			continue;
		}

		msg = rspamd_http_connection_copy_msg (session->client_conn);

		if (msg == NULL) {
			msg_err_session ("cannot copy message to send to a mirror %s: %s",
					m->name, strerror (errno));
			continue;
		}

		rspamd_http_message_remove_header (msg, "Content-Length");
		rspamd_http_message_remove_header (msg, "Key");
		msg->method = HTTP_GET;

		if (msg->url->len == 0) {
			msg->url = rspamd_fstring_append (msg->url, "/check", strlen ("/check"));
		}

		if (m->settings_id != NULL) {
			rspamd_http_message_remove_header (msg, "Settings-ID");
			rspamd_http_message_add_header (msg, "Settings-ID", m->settings_id);
		}

		bk_conn->backend_conn = rspamd_http_connection_new (NULL,
				proxy_backend_mirror_error_handler,
				proxy_backend_mirror_finish_handler,
				RSPAMD_HTTP_CLIENT_SIMPLE,
				RSPAMD_HTTP_CLIENT,
				session->ctx->keys_cache,
				NULL);

		rspamd_http_connection_set_key (bk_conn->backend_conn,
				session->ctx->local_key);
		msg->peer_key = rspamd_pubkey_ref (m->key);

		if (m->local ||
				rspamd_inet_address_is_local (rspamd_upstream_addr (bk_conn->up))) {
			rspamd_http_connection_write_message_shared (bk_conn->backend_conn,
					msg, NULL, NULL, bk_conn,
					bk_conn->backend_sock,
					bk_conn->io_tv, session->ctx->ev_base);
		}
		else {
			rspamd_http_connection_write_message (bk_conn->backend_conn,
					msg, NULL, NULL, bk_conn,
					bk_conn->backend_sock,
					bk_conn->io_tv, session->ctx->ev_base);
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

	reply = rspamd_http_new_message (HTTP_RESPONSE);
	reply->code = code;
	reply->status = rspamd_fstring_new_init (status, strlen (status));
	rspamd_http_connection_write_message (session->client_conn,
			reply, NULL, NULL, session, session->client_sock,
			&session->ctx->io_tv, session->ctx->ev_base);
}

static void
proxy_backend_master_error_handler (struct rspamd_http_connection *conn, GError *err)
{
	struct rspamd_proxy_backend_connection *bk_conn = conn->ud;
	struct rspamd_proxy_session *session;

	session = bk_conn->s;
	msg_info_session ("abnormally closing connection from backend: %s, error: %s",
		rspamd_inet_address_to_string (rspamd_upstream_addr (session->master_conn->up)),
		err->message);
	/* Terminate session immediately */
	proxy_client_write_error (session, err->code, err->message);
	proxy_backend_close_connection (session->master_conn);
}

static gint
proxy_backend_master_finish_handler (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg)
{
	struct rspamd_proxy_backend_connection *bk_conn = conn->ud;
	struct rspamd_proxy_session *session;
	rspamd_fstring_t *reply;

	session = bk_conn->s;
	rspamd_http_connection_steal_msg (session->master_conn->backend_conn);

	rspamd_http_message_remove_header (msg, "Content-Length");
	rspamd_http_message_remove_header (msg, "Key");
	rspamd_http_connection_reset (session->master_conn->backend_conn);

	if (!proxy_backend_parse_results (session, bk_conn, session->ctx->lua_state,
			bk_conn->parser_from_ref, msg->body_buf.begin, msg->body_buf.len)) {
		msg_warn_session ("cannot parse results from the master backend");
	}


	if (session->is_spamc) {
		/* We need to reformat ucl to fit with legacy spamc protocol */
		if (bk_conn->results) {
			reply = rspamd_fstring_new ();
			rspamd_ucl_torspamc_output (bk_conn->results, &reply);
			rspamd_http_message_set_body_from_fstring_steal (msg, reply);
		}
		else {
			msg_warn_session ("cannot parse results from the master backend, "
					"return them as is");
		}
	}

	rspamd_http_connection_write_message (session->client_conn,
			msg, NULL, NULL, session, session->client_sock,
			bk_conn->io_tv, session->ctx->ev_base);

	return 0;
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
	struct rspamd_http_upstream *backend = NULL;
	const rspamd_ftok_t *host;
	gchar hostbuf[512];

	if (!session->master_conn) {
		session->master_conn = rspamd_mempool_alloc0 (session->pool,
				sizeof (*session->master_conn));
		session->master_conn->s = session;
		session->master_conn->name = "master";
		host = rspamd_http_message_find_header (msg, "Host");

		/* Reset spamc legacy */
		if (msg->method >= HTTP_SYMBOLS) {
			msg->method = HTTP_GET;
			session->is_spamc = TRUE;
			msg_info_session ("enabling legacy rspamc mode for session");
		}

		if (msg->url->len == 0) {
			msg->url = rspamd_fstring_append (msg->url, "/check", strlen ("/check"));
		}

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
			session->master_conn->up = rspamd_upstream_get (backend->u,
					RSPAMD_UPSTREAM_ROUND_ROBIN, NULL, 0);
			session->master_conn->io_tv = &backend->io_tv;

			if (session->master_conn->up == NULL) {
				msg_err_session ("cannot select upstream for %s", host ? hostbuf : "default");
				goto err;
			}

			session->master_conn->backend_sock = rspamd_inet_address_connect (
					rspamd_upstream_addr (session->master_conn->up),
					SOCK_STREAM, TRUE);

			if (session->master_conn->backend_sock == -1) {
				msg_err_session ("cannot connect upstream: %s(%s)",
						host ? hostbuf : "default",
						rspamd_inet_address_to_string (rspamd_upstream_addr (session->master_conn->up)));
				rspamd_upstream_fail (session->master_conn->up);
				goto err;
			}

			if (!proxy_check_file (msg, session)) {
				goto err;
			}

			proxy_open_mirror_connections (session);
			rspamd_http_connection_steal_msg (session->client_conn);
			rspamd_http_message_remove_header (msg, "Content-Length");
			rspamd_http_message_remove_header (msg, "Key");
			rspamd_http_connection_reset (session->client_conn);
			session->shmem_ref = rspamd_http_message_shmem_ref (msg);

			session->master_conn->backend_conn = rspamd_http_connection_new (
					NULL,
					proxy_backend_master_error_handler,
					proxy_backend_master_finish_handler,
					RSPAMD_HTTP_CLIENT_SIMPLE,
					RSPAMD_HTTP_CLIENT,
					session->ctx->keys_cache,
					NULL);
			session->master_conn->parser_from_ref = backend->parser_from_ref;
			session->master_conn->parser_to_ref = backend->parser_to_ref;

			rspamd_http_connection_set_key (session->master_conn->backend_conn,
					session->ctx->local_key);
			msg->peer_key = rspamd_pubkey_ref (backend->key);

			if (backend->local ||
					rspamd_inet_address_is_local (
							rspamd_upstream_addr (session->master_conn->up))) {
				rspamd_http_connection_write_message_shared (
						session->master_conn->backend_conn,
						msg, NULL, NULL, session->master_conn,
						session->master_conn->backend_sock,
						session->master_conn->io_tv, session->ctx->ev_base);
			}
			else {
				rspamd_http_connection_write_message (
						session->master_conn->backend_conn,
						msg, NULL, NULL, session->master_conn,
						session->master_conn->backend_sock,
						session->master_conn->io_tv, session->ctx->ev_base);
			}
		}
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
	rspamd_http_connection_reset (session->client_conn);
	proxy_client_write_error (session, 404, "Backend not found");

	return 0;
}

static void
proxy_accept_socket (gint fd, short what, void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *) arg;
	struct rspamd_proxy_ctx *ctx;
	rspamd_inet_addr_t *addr;
	struct rspamd_proxy_session *session;
	gint nfd;

	ctx = worker->ctx;

	if ((nfd =
		rspamd_accept_from_socket (fd, &addr, worker->accept_events)) == -1) {
		msg_warn ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		return;
	}

	session = g_slice_alloc0 (sizeof (*session));
	REF_INIT_RETAIN (session, proxy_session_dtor);
	session->client_sock = nfd;
	session->client_addr = addr;
	session->mirror_conns = g_ptr_array_sized_new (ctx->mirrors->len);

	session->pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), "proxy");
	session->client_conn = rspamd_http_connection_new (NULL,
			proxy_client_error_handler,
			proxy_client_finish_handler,
			0,
			RSPAMD_HTTP_SERVER,
			ctx->keys_cache,
			NULL);
	session->ctx = ctx;

	if (ctx->key) {
		rspamd_http_connection_set_key (session->client_conn, ctx->key);
	}

	msg_info_session ("accepted connection from %s port %d",
			rspamd_inet_address_to_string (addr),
			rspamd_inet_address_get_port (addr));

	rspamd_http_connection_read_message_shared (session->client_conn,
			session,
			nfd,
			&ctx->io_tv,
			ctx->ev_base);
}

static void
proxy_rotate_key (gint fd, short what, void *arg)
{
	struct timeval rot_tv;
	struct rspamd_proxy_ctx *ctx = arg;
	gpointer kp;

	double_to_tv (ctx->rotate_tm, &rot_tv);
	rot_tv.tv_sec += ottery_rand_range (rot_tv.tv_sec);
	event_del (&ctx->rotate_ev);
	event_add (&ctx->rotate_ev, &rot_tv);

	kp = ctx->local_key;
	ctx->local_key = rspamd_keypair_new (RSPAMD_KEYPAIR_KEX,
			RSPAMD_CRYPTOBOX_MODE_25519);
	rspamd_keypair_unref (kp);
}

void
start_rspamd_proxy (struct rspamd_worker *worker)
{
	struct rspamd_proxy_ctx *ctx = worker->ctx;
	struct timeval rot_tv;

	ctx->ev_base = rspamd_prepare_worker (worker, "rspamd_proxy",
			proxy_accept_socket);

	ctx->resolver = dns_resolver_init (worker->srv->logger,
			ctx->ev_base,
			worker->srv->cfg);
	double_to_tv (ctx->timeout, &ctx->io_tv);
	rspamd_map_watch (worker->srv->cfg, ctx->ev_base, ctx->resolver);

	rspamd_upstreams_library_config (worker->srv->cfg, ctx->cfg->ups_ctx,
			ctx->ev_base, ctx->resolver->r);

	/* XXX: stupid default */
	ctx->keys_cache = rspamd_keypair_cache_new (256);
	ctx->local_key = rspamd_keypair_new (RSPAMD_KEYPAIR_KEX,
			RSPAMD_CRYPTOBOX_MODE_25519);

	double_to_tv (ctx->rotate_tm, &rot_tv);
	rot_tv.tv_sec += ottery_rand_range (rot_tv.tv_sec);
	event_set (&ctx->rotate_ev, -1, EV_TIMEOUT, proxy_rotate_key, ctx);
	event_base_set (ctx->ev_base, &ctx->rotate_ev);
	event_add (&ctx->rotate_ev, &rot_tv);

	event_base_loop (ctx->ev_base, 0);
	rspamd_worker_block_signals ();

	g_mime_shutdown ();
	rspamd_log_close (worker->srv->logger);

	if (ctx->key) {
		rspamd_keypair_unref (ctx->key);
	}

	rspamd_keypair_cache_destroy (ctx->keys_cache);

	exit (EXIT_SUCCESS);
}
