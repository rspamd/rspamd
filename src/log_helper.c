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
#include "libserver/cfg_file.h"
#include "libserver/cfg_rcl.h"
#include "libserver/worker_util.h"
#include "libserver/rspamd_control.h"
#include "libutil/addr.h"
#include "lua/lua_common.h"
#include "unix-std.h"
#include "utlist.h"

#ifdef HAVE_GLOB_H
#include <glob.h>
#endif

static gpointer init_log_helper (struct rspamd_config *cfg);
static void start_log_helper (struct rspamd_worker *worker);

worker_t log_helper_worker = {
		"log_helper",                /* Name */
		init_log_helper,             /* Init function */
		start_log_helper,            /* Start function */
		RSPAMD_WORKER_UNIQUE | RSPAMD_WORKER_KILLABLE,
		RSPAMD_WORKER_SOCKET_NONE,   /* No socket */
		RSPAMD_WORKER_VER            /* Version info */
};

static const guint64 rspamd_log_helper_magic = 0x1090bb46aaa74c9aULL;

/*
 * Worker's context
 */
struct log_helper_ctx {
	guint64 magic;
	/* Events base */
	struct event_base *ev_base;
	/* DNS resolver */
	struct rspamd_dns_resolver *resolver;
	/* Config */
	struct rspamd_config *cfg;
	/* END OF COMMON PART */
	struct event log_ev;
	struct rspamd_worker_lua_script *scripts;
	lua_State *L;
	gint pair[2];
};

static gpointer
init_log_helper (struct rspamd_config *cfg)
{
	struct log_helper_ctx *ctx;
	GQuark type;

	type = g_quark_try_string ("log_helper");
	(void)type;
	ctx = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (*ctx));

	ctx->magic = rspamd_log_helper_magic;
	ctx->cfg = cfg;

	return ctx;
}

static void
rspamd_log_helper_read (gint fd, short what, gpointer ud)
{
	struct log_helper_ctx *ctx = ud;
	guchar buf[8192];
	gssize r;
	guint32 n, i, nextra;
	struct rspamd_protocol_log_message_sum *sm;
	struct rspamd_worker_lua_script *sc;
	struct rspamd_config **pcfg;
	struct event_base **pevbase;

	r = read (fd, buf, sizeof (buf));

	if (r >= (gssize)sizeof (struct rspamd_protocol_log_message_sum)) {
		memcpy (&n, buf, sizeof (n));
		memcpy (&nextra, buf + sizeof (n), sizeof (nextra));

		if (n  + nextra !=
				(r - sizeof (*sm)) / sizeof (struct rspamd_protocol_log_symbol_result)) {
			msg_warn ("cannot read data from log pipe: bad length: %d elements "
					"announced but %d available", n + nextra,
					(gint)((r - sizeof (*sm)) /
					sizeof (struct rspamd_protocol_log_symbol_result)));
		}
		else {
			sm = g_malloc (r);
			memcpy (sm, buf, r);

			DL_FOREACH (ctx->scripts, sc) {
				lua_rawgeti (ctx->L, LUA_REGISTRYINDEX, sc->cbref);
				lua_pushnumber (ctx->L, sm->score);
				lua_pushnumber (ctx->L, sm->required_score);

				lua_createtable (ctx->L, n, 0);
				for (i = 0; i < n; i ++) {
					lua_createtable (ctx->L, 2, 0);
					lua_pushinteger (ctx->L, sm->results[i].id);
					lua_rawseti (ctx->L, -2, 1);
					lua_pushnumber (ctx->L, sm->results[i].score);
					lua_rawseti (ctx->L, -2, 2);

					lua_rawseti (ctx->L, -2, (i + 1));
				}

				pcfg = lua_newuserdata (ctx->L, sizeof (*pcfg));
				*pcfg = ctx->cfg;
				rspamd_lua_setclass (ctx->L, "rspamd{config}", -1);
				lua_pushinteger (ctx->L, sm->settings_id);

				lua_createtable (ctx->L, nextra, 0);
				for (i = 0; i < nextra; i ++) {
					lua_createtable (ctx->L, 2, 0);
					lua_pushinteger (ctx->L, sm->results[i + n].id);
					lua_rawseti (ctx->L, -2, 1);
					lua_pushnumber (ctx->L, sm->results[i + n].score);
					lua_rawseti (ctx->L, -2, 2);

					lua_rawseti (ctx->L, -2, (i + 1));
				}

				pevbase = lua_newuserdata (ctx->L, sizeof (*pevbase));
				*pevbase = ctx->ev_base;
				rspamd_lua_setclass (ctx->L, "rspamd{ev_base}", -1);

				if (lua_pcall (ctx->L, 7, 0, 0) != 0) {
					msg_err ("error executing log handler code: %s",
							lua_tostring (ctx->L, -1));
					lua_pop (ctx->L, 1);
				}
			}

			g_free (sm);
		}
	}
	else if (r == -1) {
		if (errno != EAGAIN && errno != EINTR) {
			msg_warn ("cannot read data from log pipe: %s", strerror (errno));
			event_del (&ctx->log_ev);
		}
	}
	else if (r == 0) {
		msg_warn ("cannot read data from log pipe: EOF");
		event_del (&ctx->log_ev);
	}
}

static void
rspamd_log_helper_reply_handler (struct rspamd_worker *worker,
		struct rspamd_srv_reply *rep, gint rep_fd,
		gpointer ud)
{
	struct log_helper_ctx *ctx = ud;

	close (ctx->pair[1]);
	msg_info ("start waiting for log events");
	event_set (&ctx->log_ev, ctx->pair[0], EV_READ | EV_PERSIST,
			rspamd_log_helper_read, ctx);
	event_base_set (ctx->ev_base, &ctx->log_ev);
	event_add (&ctx->log_ev, NULL);
}

static void
start_log_helper (struct rspamd_worker *worker)
{
	struct log_helper_ctx *ctx = worker->ctx;
	gssize r = -1;
	gint nscripts = 0;
	struct rspamd_worker_lua_script *tmp;
	static struct rspamd_srv_command srv_cmd;

	ctx->ev_base = rspamd_prepare_worker (worker,
			"log_helper",
			NULL);
	ctx->cfg = worker->srv->cfg;
	ctx->scripts = worker->cf->scripts;
	ctx->L = ctx->cfg->lua_state;
	ctx->resolver = rspamd_dns_resolver_init (worker->srv->logger,
			ctx->ev_base,
			worker->srv->cfg);
	rspamd_upstreams_library_config (worker->srv->cfg, ctx->cfg->ups_ctx,
			ctx->ev_base, ctx->resolver->r);

	DL_COUNT (worker->cf->scripts, tmp, nscripts);
	msg_info ("started log_helper worker with %d scripts", nscripts);

	r = rspamd_socketpair (ctx->pair, FALSE);

	if (r == -1) {
		msg_err ("cannot create socketpair: %s, exiting now", strerror (errno));
		/* Prevent new processes spawning */
		exit (EXIT_SUCCESS);
	}

	memset (&srv_cmd, 0, sizeof (srv_cmd));
	srv_cmd.type = RSPAMD_SRV_LOG_PIPE;
	srv_cmd.cmd.log_pipe.type = RSPAMD_LOG_PIPE_SYMBOLS;


	/* Wait for startup being completed */
	rspamd_mempool_lock_mutex (worker->srv->start_mtx);
	rspamd_srv_send_command (worker, ctx->ev_base, &srv_cmd, ctx->pair[1],
			rspamd_log_helper_reply_handler, ctx);
	rspamd_mempool_unlock_mutex (worker->srv->start_mtx);
	rspamd_lua_run_postloads (ctx->cfg->lua_state, ctx->cfg, ctx->ev_base,
			worker);
	event_base_loop (ctx->ev_base, 0);
	close (ctx->pair[0]);
	rspamd_worker_block_signals ();

	REF_RELEASE (ctx->cfg);
	rspamd_log_close (worker->srv->logger, TRUE);

	exit (EXIT_SUCCESS);
}
