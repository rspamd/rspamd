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
__attribute__((noreturn)) static void start_hs_helper (struct rspamd_worker *worker);

worker_t hs_helper_worker = {
		"hs_helper",                /* Name */
		init_hs_helper,             /* Init function */
		start_hs_helper,            /* Start function */
		RSPAMD_WORKER_UNIQUE|RSPAMD_WORKER_KILLABLE|RSPAMD_WORKER_ALWAYS_START|RSPAMD_WORKER_NO_TERMINATE_DELAY,
		RSPAMD_WORKER_SOCKET_NONE,
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
	/* Events base */
	struct ev_loop *event_loop;
	/* DNS resolver */
	struct rspamd_dns_resolver *resolver;
	/* Config */
	struct rspamd_config *cfg;
	/* END OF COMMON PART */
	gchar *hs_dir;
	gboolean loaded;
	gdouble max_time;
	gdouble recompile_time;
	ev_timer recompile_timer;
};

static gpointer
init_hs_helper (struct rspamd_config *cfg)
{
	struct hs_helper_ctx *ctx;
	GQuark type;

	type = g_quark_try_string ("hs_helper");
	ctx = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*ctx));

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
	pid_t our_pid = getpid ();

	if (stat (ctx->hs_dir, &st) == -1) {
		msg_err ("cannot stat path %s, %s",
				ctx->hs_dir,
				strerror (errno));
		return FALSE;
	}

	globbuf.gl_offs = 0;
	/*
	 * We reuse this buffer for .new patterns as well, so allocate with some
	 * margin
	 */
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
				else {
					msg_notice ("successfully removed outdated hyperscan file: %s",
							globbuf.gl_pathv[i]);
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
			/* Check if we have a pid in the filename */
			const gchar *end_num = globbuf.gl_pathv[i] +
					strlen (globbuf.gl_pathv[i]) - (sizeof (".hs.new") - 1);
			const gchar *p = end_num - 1;
			pid_t foreign_pid = -1;

			while (p > globbuf.gl_pathv[i]) {
				if (g_ascii_isdigit (*p)) {
					p --;
				}
				else {
					p ++;
					break;
				}
			}

			gulong ul;
			if (p < end_num && rspamd_strtoul (p, end_num - p, &ul)) {
				foreign_pid = ul;
			}

			/*
			 * Remove only files that was left by us or some non-existing process
			 * There could be another race condition but it would just leave
			 * extra files which is relatively innocent?
			 */
			if (foreign_pid == -1 || foreign_pid == our_pid || kill (foreign_pid, 0) == -1) {
				if (unlink(globbuf.gl_pathv[i]) == -1) {
					msg_err ("cannot unlink %s: %s", globbuf.gl_pathv[i],
							strerror(errno));
					ret = FALSE;
				}
				else {
					msg_notice ("successfully removed outdated hyperscan temporary file: %s; "
								"pid of the file creator process: %P",
							globbuf.gl_pathv[i],
							foreign_pid);
				}
			}
			else {
				msg_notice ("skip removal of the hyperscan temporary file: %s; "
							"pid of the file creator process: %P",
						globbuf.gl_pathv[i],
						foreign_pid);
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

/* Bad hack, but who cares */
static gboolean hack_global_forced;

static void
rspamd_rs_delayed_cb (EV_P_ ev_timer *w, int revents)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)w->data;
	static struct rspamd_srv_command srv_cmd;
	struct hs_helper_ctx *ctx;

	ctx = (struct hs_helper_ctx *)worker->ctx;
	memset (&srv_cmd, 0, sizeof (srv_cmd));
	srv_cmd.type = RSPAMD_SRV_HYPERSCAN_LOADED;
	rspamd_strlcpy (srv_cmd.cmd.hs_loaded.cache_dir, ctx->hs_dir,
			sizeof (srv_cmd.cmd.hs_loaded.cache_dir));
	srv_cmd.cmd.hs_loaded.forced = hack_global_forced;
	hack_global_forced = FALSE;

	rspamd_srv_send_command (worker,
			ctx->event_loop, &srv_cmd, -1, NULL, NULL);
	ev_timer_stop (EV_A_ w);
	g_free (w);

	ev_timer_again (EV_A_ &ctx->recompile_timer);
}

static void
rspamd_rs_compile_cb (guint ncompiled, GError *err, void *cbd)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)cbd;
	ev_timer *tm;
	ev_tstamp when = 0.0;
	struct hs_helper_ctx *ctx;

	ctx = (struct hs_helper_ctx *)worker->ctx;

	if (err != NULL) {
		/* Failed to compile: log and go out */
		msg_err ("cannot compile Hyperscan database: %e", err);

		return;
	}

	if (ncompiled > 0) {
		/* Enforce update for other workers */
		hack_global_forced = TRUE;
	}

	/*
	 * Do not send notification unless all other workers are started
	 * XXX: now we just sleep for 1 seconds to ensure that
	 */
	if (!ctx->loaded) {
		when = 1.0; /* Postpone */
		ctx->loaded = TRUE;
		msg_info ("compiled %d regular expressions to the hyperscan tree, "
				  "postpone loaded notification for %.0f seconds to avoid races",
				ncompiled,
				when);
	}
	else {
		msg_info ("compiled %d regular expressions to the hyperscan tree, "
				  "send loaded notification",
				ncompiled);
	}

	tm = g_malloc0 (sizeof (*tm));
	tm->data = (void *)worker;
	ev_timer_init (tm, rspamd_rs_delayed_cb, when, 0);
	ev_timer_start (ctx->event_loop, tm);
}

static gboolean
rspamd_rs_compile (struct hs_helper_ctx *ctx, struct rspamd_worker *worker,
		gboolean forced)
{
#ifndef __aarch64__
	if (!(ctx->cfg->libs_ctx->crypto_ctx->cpu_config & CPUID_SSSE3)) {
		msg_warn ("CPU doesn't have SSSE3 instructions set "
				"required for hyperscan, disable hyperscan compilation");
		return FALSE;
	}
#endif

	if (!rspamd_hs_helper_cleanup_dir (ctx, forced)) {
		msg_warn ("cannot cleanup cache dir '%s'", ctx->hs_dir);
	}

	hack_global_forced = forced; /* killmeplease */
	rspamd_re_cache_compile_hyperscan (ctx->cfg->re_cache,
			ctx->hs_dir, ctx->max_time, !forced,
			ctx->event_loop,
			rspamd_rs_compile_cb,
			(void *)worker);

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

	/* Stop recompile */
	ev_timer_stop (ctx->event_loop, &ctx->recompile_timer);
	rspamd_rs_compile (ctx, worker, TRUE);

	return TRUE;
}

static void
rspamd_hs_helper_timer (EV_P_ ev_timer *w, int revents)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)w->data;
	struct hs_helper_ctx *ctx;
	double tim;

	ctx = worker->ctx;
	tim = rspamd_time_jitter (ctx->recompile_time, 0);
	w->repeat = tim;
	rspamd_rs_compile (ctx, worker, FALSE);
}

static void
start_hs_helper (struct rspamd_worker *worker)
{
	struct hs_helper_ctx *ctx = worker->ctx;
	double tim;

	g_assert (rspamd_worker_check_context (worker->ctx, rspamd_hs_helper_magic));
	ctx->cfg = worker->srv->cfg;

	if (ctx->hs_dir == NULL) {
		ctx->hs_dir = ctx->cfg->hs_cache_dir;
	}
	if (ctx->hs_dir == NULL) {
		ctx->hs_dir = RSPAMD_DBDIR "/";
	}

	ctx->event_loop = rspamd_prepare_worker (worker,
			"hs_helper",
			NULL);

	if (!rspamd_rs_compile (ctx, worker, FALSE)) {
		/* Tell main not to respawn more workers */
		exit (EXIT_SUCCESS);
	}

	rspamd_control_worker_add_cmd_handler (worker, RSPAMD_CONTROL_RECOMPILE,
			rspamd_hs_helper_reload, ctx);

	ctx->recompile_timer.data = worker;
	tim = rspamd_time_jitter (ctx->recompile_time, 0);
	ev_timer_init (&ctx->recompile_timer, rspamd_hs_helper_timer, tim, 0.0);
	ev_timer_start (ctx->event_loop, &ctx->recompile_timer);

	ev_loop (ctx->event_loop, 0);
	rspamd_worker_block_signals ();

	rspamd_log_close (worker->srv->logger);
	REF_RELEASE (ctx->cfg);

	exit (EXIT_SUCCESS);
}
