/* Copyright (c) 2010-2012, Vsevolod Stakhov
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


#include "config.h"
#include "util.h"
#include "main.h"
#include "protocol.h"
#include "upstream.h"
#include "cfg_file.h"
#include "url.h"
#include "message.h"
#include "map.h"
#include "dns.h"

#include "lua/lua_common.h"

#ifdef WITH_GPERF_TOOLS
#   include <glib/gprintf.h>
#endif

/* 60 seconds for worker's IO */
#define DEFAULT_WORKER_IO_TIMEOUT 60000

gpointer init_lua_worker (struct rspamd_config *cfg);
void start_lua_worker (struct rspamd_worker *worker);

worker_t lua_worker = {
	"lua",                  /* Name */
	init_lua_worker,        /* Init function */
	start_lua_worker,       /* Start function */
	TRUE,                   /* Has socket */
	FALSE,                  /* Non unique */
	FALSE,                  /* Non threaded */
	TRUE,                   /* Killable */
	SOCK_STREAM             /* TCP socket */
};

/*
 * Worker's context
 */
struct rspamd_lua_worker_ctx {
	/* DNS resolver */
	struct rspamd_dns_resolver *resolver;
	/* Events base */
	struct event_base *ev_base;
	/* Other params */
	GHashTable *params;
	/* Lua script to load */
	gchar *file;
	/* Lua state */
	lua_State *L;
	/* Callback for accept */
	gint cbref_accept;
	/* Callback for finishing */
	gint cbref_fin;
	/* Config file */
	struct rspamd_config *cfg;
	/* The rest options */
	ucl_object_t *opts;
};

/* Lua bindings */
LUA_FUNCTION_DEF (worker, get_ev_base);
LUA_FUNCTION_DEF (worker, register_accept_callback);
LUA_FUNCTION_DEF (worker, register_exit_callback);
LUA_FUNCTION_DEF (worker, get_option);
LUA_FUNCTION_DEF (worker, get_resolver);
LUA_FUNCTION_DEF (worker, get_cfg);

static const struct luaL_reg lua_workerlib_m[] = {
	LUA_INTERFACE_DEF (worker, get_ev_base),
	LUA_INTERFACE_DEF (worker, register_accept_callback),
	LUA_INTERFACE_DEF (worker, register_exit_callback),
	LUA_INTERFACE_DEF (worker, get_option),
	LUA_INTERFACE_DEF (worker, get_resolver),
	LUA_INTERFACE_DEF (worker, get_cfg),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

/* Basic functions of LUA API for worker object */
static gint
luaopen_lua_worker (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{worker}", lua_workerlib_m);
	luaL_register (L, "rspamd_worker", null_reg);

	lua_pop (L, 1);                      /* remove metatable from stack */

	return 1;
}

struct rspamd_lua_worker_ctx *
lua_check_lua_worker (lua_State * L)
{
	void *ud = luaL_checkudata (L, 1, "rspamd{worker}");
	luaL_argcheck (L, ud != NULL, 1, "'worker' expected");
	return ud ? *((struct rspamd_lua_worker_ctx **)ud) : NULL;
}

static int
lua_worker_get_ev_base (lua_State *L)
{
	struct rspamd_lua_worker_ctx *ctx = lua_check_lua_worker (L);
	struct event_base **pbase;

	if (ctx) {
		pbase = lua_newuserdata (L, sizeof (struct event_base *));
		rspamd_lua_setclass (L, "rspamd{ev_base}", -1);
		*pbase = ctx->ev_base;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_worker_register_accept_callback (lua_State *L)
{
	struct rspamd_lua_worker_ctx *ctx = lua_check_lua_worker (L);

	if (ctx) {
		if (!lua_isfunction (L, 2)) {
			msg_err ("invalid callback passed");
			lua_pushnil (L);
		}
		else {
			lua_pushvalue (L, 2);
			ctx->cbref_accept = luaL_ref (L, LUA_REGISTRYINDEX);
			return 0;
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_worker_register_exit_callback (lua_State *L)
{
	struct rspamd_lua_worker_ctx *ctx = lua_check_lua_worker (L);

	if (ctx) {
		if (!lua_isfunction (L, 2)) {
			msg_err ("invalid callback passed");
			lua_pushnil (L);
		}
		else {
			lua_pushvalue (L, 2);
			ctx->cbref_fin = luaL_ref (L, LUA_REGISTRYINDEX);
			return 0;
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/* XXX: This fucntions should be rewritten completely */
static int
lua_worker_get_option (lua_State *L)
{
	struct rspamd_lua_worker_ctx *ctx = lua_check_lua_worker (L);
	const ucl_object_t *val;
	const gchar *name;

	if (ctx) {
		name = luaL_checkstring (L, 2);
		if (name == NULL) {
			msg_err ("no name specified");
			lua_pushnil (L);
		}
		else {
			val = ucl_object_find_key (ctx->opts, name);
			if (val == NULL) {
				lua_pushnil (L);
			}
			else {
				ucl_object_push_lua (L, val, TRUE);
			}
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_worker_get_resolver (lua_State *L)
{
	struct rspamd_lua_worker_ctx *ctx = lua_check_lua_worker (L);
	struct rspamd_dns_resolver **presolver;

	if (ctx) {
		presolver = lua_newuserdata (L, sizeof (gpointer));
		rspamd_lua_setclass (L, "rspamd{resolver}", -1);
		*presolver = ctx->resolver;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_worker_get_cfg (lua_State *L)
{
	struct rspamd_lua_worker_ctx *ctx = lua_check_lua_worker (L);
	struct rspamd_config **pcfg;

	if (ctx) {
		pcfg = lua_newuserdata (L, sizeof (gpointer));
		rspamd_lua_setclass (L, "rspamd{config}", -1);
		*pcfg = ctx->cfg;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/* End of lua API */

/*
 * Accept new connection and construct task
 */
static void
lua_accept_socket (gint fd, short what, void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *) arg;
	struct rspamd_lua_worker_ctx *ctx, **pctx;
	gint nfd;
	lua_State *L;
	rspamd_inet_addr_t addr;

	ctx = worker->ctx;
	L = ctx->L;

	if ((nfd =
		rspamd_accept_from_socket (fd, &addr)) == -1) {
		msg_warn ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		return;
	}

	msg_info ("accepted connection from %s port %d",
		rspamd_inet_address_to_string (&addr),
		rspamd_inet_address_get_port (&addr));

	/* Call finalizer function */
	lua_rawgeti (L, LUA_REGISTRYINDEX, ctx->cbref_accept);
	pctx = lua_newuserdata (L, sizeof (gpointer));
	rspamd_lua_setclass (L, "rspamd{worker}", -1);
	*pctx = ctx;
	lua_pushinteger (L, nfd);
	lua_pushstring (L, rspamd_inet_address_to_string (&addr));
	lua_pushinteger (L, 0);


	if (lua_pcall (L, 4, 0, 0) != 0) {
		msg_info ("call to worker accept failed: %s", lua_tostring (L, -1));
	}
}

static gboolean
rspamd_lua_worker_parser (ucl_object_t *obj, gpointer ud)
{
	struct rspamd_lua_worker_ctx *ctx = ud;

	ctx->opts = obj;

	return TRUE;
}

gpointer
init_lua_worker (struct rspamd_config *cfg)
{
	struct rspamd_lua_worker_ctx *ctx;
	GQuark type;

	type = g_quark_try_string ("lua");

	ctx = g_malloc0 (sizeof (struct rspamd_lua_worker_ctx));
	ctx->params = g_hash_table_new_full (rspamd_str_hash,
			rspamd_str_equal,
			g_free,
			(GDestroyNotify)g_list_free);


	rspamd_rcl_register_worker_option (cfg, type, "file",
		rspamd_rcl_parse_struct_string, ctx,
		G_STRUCT_OFFSET (struct rspamd_lua_worker_ctx, file), 0);

	rspamd_rcl_register_worker_parser (cfg, type, rspamd_lua_worker_parser,
		ctx);

	return ctx;
}

/*
 * Start worker process
 */
void
start_lua_worker (struct rspamd_worker *worker)
{
	struct rspamd_lua_worker_ctx *ctx = worker->ctx, **pctx;
	lua_State *L;

#ifdef WITH_PROFILER
	extern void _start (void), etext (void);
	monstartup ((u_long) & _start, (u_long) & etext);
#endif

	ctx->ev_base = rspamd_prepare_worker (worker,
			"lua_worker",
			lua_accept_socket);

	L = worker->srv->cfg->lua_state;
	ctx->L = L;
	ctx->cfg = worker->srv->cfg;

	ctx->resolver = dns_resolver_init (worker->srv->logger,
			ctx->ev_base,
			worker->srv->cfg);

	/* Open worker's lib */
	luaopen_lua_worker (L);

	if (ctx->file == NULL) {
		msg_err ("No lua script defined, so no reason to exist");
		exit (EXIT_SUCCESS);
	}
	if (access (ctx->file, R_OK) == -1) {
		msg_err ("Error reading lua script %s: %s", ctx->file,
			strerror (errno));
		exit (EXIT_SUCCESS);
	}

	pctx = lua_newuserdata (L, sizeof (gpointer));
	rspamd_lua_setclass (L, "rspamd{worker}", -1);
	lua_setglobal (L, "rspamd_worker");
	*pctx = ctx;

	if (luaL_dofile (L, ctx->file) != 0) {
		msg_err ("Error executing lua script %s: %s", ctx->file,
			lua_tostring (L, -1));
		exit (EXIT_SUCCESS);
	}

	if (ctx->cbref_accept == 0) {
		msg_err ("No accept function defined, so no reason to exist");
		exit (EXIT_SUCCESS);
	}

	/* Maps events */
	rspamd_map_watch (worker->srv->cfg, ctx->ev_base);

	event_base_loop (ctx->ev_base, 0);
	luaL_unref (L, LUA_REGISTRYINDEX, ctx->cbref_accept);
	if (ctx->cbref_fin != 0) {
		/* Call finalizer function */
		lua_rawgeti (L, LUA_REGISTRYINDEX, ctx->cbref_fin);
		pctx = lua_newuserdata (L, sizeof (gpointer));
		rspamd_lua_setclass (L, "rspamd{worker}", -1);
		*pctx = ctx;
		if (lua_pcall (L, 1, 0, 0) != 0) {
			msg_info ("call to worker finalizer failed: %s", lua_tostring (L,
				-1));
		}
		/* Free resources */
		luaL_unref (L, LUA_REGISTRYINDEX, ctx->cbref_fin);
	}

	rspamd_log_close (rspamd_main->logger);
	exit (EXIT_SUCCESS);
}

/*
 * vi:ts=4
 */

