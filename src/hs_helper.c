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
#include "unix-std.h"

#ifdef HAVE_GLOB_H
#include <glob.h>
#endif

static gpointer init_hs_helper (struct rspamd_config *cfg);
static void start_hs_helper (struct rspamd_worker *worker);

worker_t hs_helper_worker = {
		"hs_helper",                /* Name */
		init_hs_helper,             /* Init function */
		start_hs_helper,            /* Start function */
		RSPAMD_WORKER_UNIQUE|RSPAMD_WORKER_KILLABLE|RSPAMD_WORKER_ALWAYS_START,
		RSPAMD_WORKER_SOCKET_NONE,  /* No socket */
		RSPAMD_WORKER_VER           /* Version info */
};

static const gdouble default_max_time = 1.0;
static const gdouble default_recompile_time = 60.0;
static const guint64 rspamd_hs_helper_magic = 0x22d310157a2288a0ULL;

/*
 * Worker's context
 */
struct hs_helper_ctx {
	guint64 magic;
	gchar *hs_dir;
	gboolean loaded;
	gdouble max_time;
	gdouble recompile_time;
	struct rspamd_config *cfg;
	struct event recompile_timer;
	struct event_base *ev_base;
};

static gpointer
init_hs_helper (struct rspamd_config *cfg)
{
	struct hs_helper_ctx *ctx;
	GQuark type;

	type = g_quark_try_string ("hs_helper");
	ctx = g_malloc0 (sizeof (*ctx));

	ctx->magic = rspamd_hs_helper_magic;
	ctx->cfg = cfg;
	ctx->hs_dir = NULL;
	ctx->max_time = default_max_time;
	ctx->recompile_time = default_recompile_time;

	rspamd_rcl_register_worker_option (cfg,
			type,
			"cache_dir",
			rspamd_rcl_parse_struct_string,
			ctx,
			G_STRUCT_OFFSET (struct hs_helper_ctx, hs_dir),
			0,
			"Directory where to save hyperscan compiled expressions");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"max_time",
			rspamd_rcl_parse_struct_time,
			ctx,
			G_STRUCT_OFFSET (struct hs_helper_ctx, max_time),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			"Maximum time to wait for compilation of a single expression");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"recompile",
			rspamd_rcl_parse_struct_time,
			ctx,
			G_STRUCT_OFFSET (struct hs_helper_ctx, recompile_time),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			"Time between recompilation checks");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"timeout",
			rspamd_rcl_parse_struct_time,
			ctx,
			G_STRUCT_OFFSET (struct hs_helper_ctx, max_time),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			"Maximum time to wait for compilation of a single expression");

	return ctx;
}

/**
 * Clean
 */
static gboolean
rspamd_hs_helper_cleanup_dir (struct hs_helper_ctx *ctx, gboolean forced)
{
	struct stat st;
	glob_t globbuf;
	guint len, i;
	gint rc;
	gchar *pattern;
	gboolean ret = TRUE;

	if (stat (ctx->hs_dir, &st) == -1) {
		msg_err ("cannot stat path %s, %s",
				ctx->hs_dir,
				strerror (errno));
		return FALSE;
	}

	globbuf.gl_offs = 0;
	len = strlen (ctx->hs_dir) + 1 + sizeof ("*.hs.new") + 2;
	pattern = g_malloc (len);
	rspamd_snprintf (pattern, len, "%s%c%s", ctx->hs_dir, G_DIR_SEPARATOR, "*.hs");

	if ((rc = glob (pattern, 0, NULL, &globbuf)) == 0) {
		for (i = 0; i < globbuf.gl_pathc; i++) {
			if (forced ||
					!rspamd_re_cache_is_valid_hyperscan_file (ctx->cfg->re_cache,
						globbuf.gl_pathv[i], TRUE, TRUE)) {
				if (unlink (globbuf.gl_pathv[i]) == -1) {
					msg_err ("cannot unlink %s: %s", globbuf.gl_pathv[i],
							strerror (errno));
					ret = FALSE;
				}
			}
		}
	}
	else if (rc != GLOB_NOMATCH) {
		msg_err ("glob %s failed: %s", pattern, strerror (errno));
		ret = FALSE;
	}

	globfree (&globbuf);

	memset (&globbuf, 0, sizeof (globbuf));
	rspamd_snprintf (pattern, len, "%s%c%s", ctx->hs_dir, G_DIR_SEPARATOR, "*.hs.new");
	if ((rc = glob (pattern, 0, NULL, &globbuf)) == 0) {
		for (i = 0; i < globbuf.gl_pathc; i++) {
			if (unlink (globbuf.gl_pathv[i]) == -1) {
				msg_err ("cannot unlink %s: %s", globbuf.gl_pathv[i],
						strerror (errno));
				ret = FALSE;
			}
		}
	}
	else if (rc != GLOB_NOMATCH) {
		msg_err ("glob %s failed: %s", pattern, strerror (errno));
		ret = FALSE;
	}

	globfree (&globbuf);
	g_free (pattern);

	return ret;
}

static gboolean
rspamd_rs_compile (struct hs_helper_ctx *ctx, struct rspamd_worker *worker,
		gboolean forced)
{
	GError *err = NULL;
	static struct rspamd_srv_command srv_cmd;
	gint ncompiled;

	if (!rspamd_hs_helper_cleanup_dir (ctx, forced)) {
		msg_warn ("cannot cleanup cache dir '%s'", ctx->hs_dir);
	}

	if ((ncompiled = rspamd_re_cache_compile_hyperscan (ctx->cfg->re_cache,
			ctx->hs_dir, ctx->max_time, !forced,
			&err)) == -1) {
		msg_err ("failed to compile re cache: %e", err);
		g_error_free (err);

		return FALSE;
	}

	if (ncompiled > 0) {
		msg_info ("compiled %d regular expressions to the hyperscan tree",
				ncompiled);
		forced = TRUE;
	}

	/*
	 * Do not send notification unless all other workers are started
	 * XXX: now we just sleep for 5 seconds to ensure that
	 */
	if (!ctx->loaded) {
		sleep (5);
		ctx->loaded = TRUE;
	}

	srv_cmd.type = RSPAMD_SRV_HYPERSCAN_LOADED;
	srv_cmd.cmd.hs_loaded.cache_dir = ctx->hs_dir;
	srv_cmd.cmd.hs_loaded.forced = forced;

	rspamd_srv_send_command (worker, ctx->ev_base, &srv_cmd, -1, NULL, NULL);

	return TRUE;
}

static gboolean
rspamd_hs_helper_reload (struct rspamd_main *rspamd_main,
		struct rspamd_worker *worker, gint fd,
		gint attached_fd,
		struct rspamd_control_command *cmd,
		gpointer ud)
{
	struct rspamd_control_reply rep;
	struct hs_helper_ctx *ctx = ud;

	msg_info ("recompiling hyperscan expressions after receiving reload command");
	memset (&rep, 0, sizeof (rep));
	rep.type = RSPAMD_CONTROL_RECOMPILE;
	rep.reply.recompile.status = 0;

	/* We write reply before actual recompilation as it takes a lot of time */
	if (write (fd, &rep, sizeof (rep)) != sizeof (rep)) {
		msg_err ("cannot write reply to the control socket: %s",
				strerror (errno));
	}

	rspamd_rs_compile (ctx, worker, TRUE);

	return TRUE;
}

static void
rspamd_hs_helper_timer (gint fd, short what, gpointer ud)
{
	struct rspamd_worker *worker = ud;
	struct hs_helper_ctx *ctx;
	struct timeval tv;
	double tim;

	ctx = worker->ctx;
	tim = rspamd_time_jitter (ctx->recompile_time, 0);
	double_to_tv (tim, &tv);
	event_del (&ctx->recompile_timer);
	rspamd_rs_compile (ctx, worker, FALSE);
	event_add (&ctx->recompile_timer, &tv);
}

static void
start_hs_helper (struct rspamd_worker *worker)
{
	struct hs_helper_ctx *ctx = worker->ctx;
	struct timeval tv;
	double tim;


	if (ctx->hs_dir == NULL) {
		ctx->hs_dir = ctx->cfg->hs_cache_dir;
	}
	if (ctx->hs_dir == NULL) {
		ctx->hs_dir = RSPAMD_DBDIR "/";
	}

	ctx->ev_base = rspamd_prepare_worker (worker,
			"hs_helper",
			NULL);

	if (!rspamd_rs_compile (ctx, worker, FALSE)) {
		/* Tell main not to respawn more workers */
		exit (EXIT_SUCCESS);
	}

	rspamd_control_worker_add_cmd_handler (worker, RSPAMD_CONTROL_RECOMPILE,
			rspamd_hs_helper_reload, ctx);

	event_set (&ctx->recompile_timer, -1, EV_TIMEOUT, rspamd_hs_helper_timer,
			worker);
	event_base_set (ctx->ev_base, &ctx->recompile_timer);
	tim = rspamd_time_jitter (ctx->recompile_time, 0);
	double_to_tv (tim, &tv);
	event_add (&ctx->recompile_timer, &tv);
	event_base_loop (ctx->ev_base, 0);
	rspamd_worker_block_signals ();

	rspamd_log_close (worker->srv->logger);

	exit (EXIT_SUCCESS);
}
