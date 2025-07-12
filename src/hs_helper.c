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

static gpointer init_hs_helper(struct rspamd_config *cfg);
__attribute__((noreturn)) static void start_hs_helper(struct rspamd_worker *worker);

worker_t hs_helper_worker = {
	"hs_helper",     /* Name */
	init_hs_helper,  /* Init function */
	start_hs_helper, /* Start function */
	RSPAMD_WORKER_UNIQUE | RSPAMD_WORKER_KILLABLE | RSPAMD_WORKER_ALWAYS_START | RSPAMD_WORKER_NO_TERMINATE_DELAY,
	RSPAMD_WORKER_SOCKET_NONE,
	RSPAMD_WORKER_VER /* Version info */
};

static const double default_max_time = 1.0;
static const double default_recompile_time = 60.0;
static const uint64_t rspamd_hs_helper_magic = 0x22d310157a2288a0ULL;

/*
 * Worker's context
 */
struct hs_helper_ctx {
	uint64_t magic;
	/* Events base */
	struct ev_loop *event_loop;
	/* DNS resolver */
	struct rspamd_dns_resolver *resolver;
	/* Config */
	struct rspamd_config *cfg;
	/* END OF COMMON PART */
	char *hs_dir;
	gboolean loaded;
	gboolean workers_ready;
	double max_time;
	double recompile_time;
	ev_timer recompile_timer;
};

static gpointer
init_hs_helper(struct rspamd_config *cfg)
{
	struct hs_helper_ctx *ctx;
	GQuark type;

	type = g_quark_try_string("hs_helper");
	ctx = rspamd_mempool_alloc0(cfg->cfg_pool, sizeof(*ctx));

	ctx->magic = rspamd_hs_helper_magic;
	ctx->cfg = cfg;
	ctx->hs_dir = NULL;
	ctx->loaded = FALSE;
	ctx->workers_ready = FALSE;
	ctx->max_time = default_max_time;
	ctx->recompile_time = default_recompile_time;

	rspamd_rcl_register_worker_option(cfg,
									  type,
									  "cache_dir",
									  rspamd_rcl_parse_struct_string,
									  ctx,
									  G_STRUCT_OFFSET(struct hs_helper_ctx, hs_dir),
									  0,
									  "Directory where to save hyperscan compiled expressions");
	rspamd_rcl_register_worker_option(cfg,
									  type,
									  "max_time",
									  rspamd_rcl_parse_struct_time,
									  ctx,
									  G_STRUCT_OFFSET(struct hs_helper_ctx, max_time),
									  RSPAMD_CL_FLAG_TIME_FLOAT,
									  "Maximum time to wait for compilation of a single expression");
	rspamd_rcl_register_worker_option(cfg,
									  type,
									  "recompile",
									  rspamd_rcl_parse_struct_time,
									  ctx,
									  G_STRUCT_OFFSET(struct hs_helper_ctx, recompile_time),
									  RSPAMD_CL_FLAG_TIME_FLOAT,
									  "Time between recompilation checks");
	rspamd_rcl_register_worker_option(cfg,
									  type,
									  "timeout",
									  rspamd_rcl_parse_struct_time,
									  ctx,
									  G_STRUCT_OFFSET(struct hs_helper_ctx, max_time),
									  RSPAMD_CL_FLAG_TIME_FLOAT,
									  "Maximum time to wait for compilation of a single expression");

	return ctx;
}

/**
 * Clean
 */
static gboolean
rspamd_hs_helper_cleanup_dir(struct hs_helper_ctx *ctx, gboolean forced)
{
	struct stat st;
	glob_t globbuf;
	unsigned int len, i;
	int rc;
	char *pattern;
	gboolean ret = TRUE;
	pid_t our_pid = getpid();

	if (getenv("RSPAMD_NO_CLEANUP")) {
		/* Skip all cleanup */
		return TRUE;
	}

	if (stat(ctx->hs_dir, &st) == -1) {
		msg_err("cannot stat path %s, %s",
				ctx->hs_dir,
				strerror(errno));
		return FALSE;
	}

	globbuf.gl_offs = 0;
	/*
	 * We reuse this buffer for .new patterns as well, so allocate with some
	 * margin
	 */
	len = strlen(ctx->hs_dir) + 1 + sizeof("*.hs") + sizeof(G_DIR_SEPARATOR);
	pattern = g_malloc(len);
	rspamd_snprintf(pattern, len, "%s%c%s", ctx->hs_dir, G_DIR_SEPARATOR, "*.hs");

	if ((rc = glob(pattern, 0, NULL, &globbuf)) == 0) {
		for (i = 0; i < globbuf.gl_pathc; i++) {
			GError *err = NULL;

			if (forced) {
				g_set_error(&err, g_quark_from_static_string("re_cache"),
							0, "forced removal");
			}

			if (forced ||
				!rspamd_re_cache_is_valid_hyperscan_file(ctx->cfg->re_cache,
														 globbuf.gl_pathv[i], TRUE, TRUE, &err)) {
				if (unlink(globbuf.gl_pathv[i]) == -1) {
					msg_err("cannot unlink %s: %s; reason for expiration: %e", globbuf.gl_pathv[i],
							strerror(errno), err);
					ret = FALSE;
				}
				else {
					msg_notice("successfully removed outdated hyperscan file: %s; reason for expiration: %e",
							   globbuf.gl_pathv[i], err);
				}
			}

			if (err) {
				g_error_free(err);
			}
		}
	}
	else if (rc != GLOB_NOMATCH) {
		msg_err("glob %s failed: %s", pattern, strerror(errno));
		ret = FALSE;
	}

	globfree(&globbuf);

	memset(&globbuf, 0, sizeof(globbuf));
	rspamd_snprintf(pattern, len, "%s%c%s", ctx->hs_dir, G_DIR_SEPARATOR, "*.hs.new");
	if ((rc = glob(pattern, 0, NULL, &globbuf)) == 0) {
		for (i = 0; i < globbuf.gl_pathc; i++) {
			/* Check if we have a pid in the filename */
			const char *end_num = globbuf.gl_pathv[i] +
								  strlen(globbuf.gl_pathv[i]) - (sizeof(".hs.new") - 1);
			const char *p = end_num - 1;
			pid_t foreign_pid = -1;

			while (p > globbuf.gl_pathv[i]) {
				if (g_ascii_isdigit(*p)) {
					p--;
				}
				else {
					p++;
					break;
				}
			}

			gulong ul;
			if (p < end_num && rspamd_strtoul(p, end_num - p, &ul)) {
				foreign_pid = ul;
			}

			/*
			 * Remove only files that was left by us or some non-existing process
			 * There could be another race condition but it would just leave
			 * extra files which is relatively innocent?
			 */
			if (foreign_pid == -1 || foreign_pid == our_pid || kill(foreign_pid, 0) == -1) {
				if (unlink(globbuf.gl_pathv[i]) == -1) {
					msg_err("cannot unlink %s: %s", globbuf.gl_pathv[i],
							strerror(errno));
					ret = FALSE;
				}
				else {
					msg_notice("successfully removed outdated hyperscan temporary file: %s; "
							   "pid of the file creator process: %P",
							   globbuf.gl_pathv[i],
							   foreign_pid);
				}
			}
			else {
				msg_notice("skip removal of the hyperscan temporary file: %s; "
						   "pid of the file creator process: %P",
						   globbuf.gl_pathv[i],
						   foreign_pid);
			}
		}
	}
	else if (rc != GLOB_NOMATCH) {
		msg_err("glob %s failed: %s", pattern, strerror(errno));
		ret = FALSE;
	}

	globfree(&globbuf);
	g_free(pattern);

	return ret;
}


struct rspamd_hs_helper_compile_cbdata {
	struct rspamd_worker *worker;
	struct hs_helper_ctx *ctx;
	unsigned int total_compiled;
	unsigned int scopes_remaining;
	gboolean forced;
	gboolean workers_ready;
};

static void
rspamd_rs_send_final_notification(struct rspamd_hs_helper_compile_cbdata *cbd)
{
	struct rspamd_worker *worker = cbd->worker;
	struct hs_helper_ctx *ctx = cbd->ctx;
	static struct rspamd_srv_command srv_cmd;

	memset(&srv_cmd, 0, sizeof(srv_cmd));
	srv_cmd.type = RSPAMD_SRV_HYPERSCAN_LOADED;
	rspamd_strlcpy(srv_cmd.cmd.hs_loaded.cache_dir, ctx->hs_dir,
				   sizeof(srv_cmd.cmd.hs_loaded.cache_dir));
	srv_cmd.cmd.hs_loaded.forced = cbd->forced;
	srv_cmd.cmd.hs_loaded.scope[0] = '\0'; /* NULL scope means all scopes */

	rspamd_srv_send_command(worker,
							ctx->event_loop, &srv_cmd, -1, NULL, NULL);

	msg_info("sent final hyperscan loaded notification (%d total expressions compiled)",
			 cbd->total_compiled);

	g_free(cbd);
	ev_timer_stop(ctx->event_loop, &ctx->recompile_timer);
}

static void
rspamd_rs_compile_scoped_cb(const char *scope, unsigned int ncompiled, GError *err, void *cbd)
{
	struct rspamd_hs_helper_compile_cbdata *compile_cbd =
		(struct rspamd_hs_helper_compile_cbdata *) cbd;
	struct rspamd_worker *worker = compile_cbd->worker;
	struct hs_helper_ctx *ctx = compile_cbd->ctx;
	static struct rspamd_srv_command srv_cmd;

	if (err != NULL) {
		/* Failed to compile: log and continue */
		msg_err("cannot compile Hyperscan database for scope %s: %e",
				scope ? scope : "default", err);
	}
	else {
		if (ncompiled > 0) {
			compile_cbd->total_compiled += ncompiled;

			/* Send notification for this specific scope */
			memset(&srv_cmd, 0, sizeof(srv_cmd));
			srv_cmd.type = RSPAMD_SRV_HYPERSCAN_LOADED;
			rspamd_strlcpy(srv_cmd.cmd.hs_loaded.cache_dir, ctx->hs_dir,
						   sizeof(srv_cmd.cmd.hs_loaded.cache_dir));
			srv_cmd.cmd.hs_loaded.forced = compile_cbd->forced;
			if (scope) {
				rspamd_strlcpy(srv_cmd.cmd.hs_loaded.scope, scope,
							   sizeof(srv_cmd.cmd.hs_loaded.scope));
			}
			else {
				srv_cmd.cmd.hs_loaded.scope[0] = '\0';
			}

			rspamd_srv_send_command(worker,
									ctx->event_loop, &srv_cmd, -1, NULL, NULL);

			msg_info("compiled %d regular expressions for scope %s",
					 ncompiled, scope ? scope : "default");
		}
	}

	compile_cbd->scopes_remaining--;

	/* Check if all scopes are done */
	if (compile_cbd->scopes_remaining == 0) {
		if (compile_cbd->workers_ready) {
			/* Workers are ready, send notification immediately */
			msg_info("compiled %d total regular expressions to the hyperscan tree, "
					 "send final notification",
					 compile_cbd->total_compiled);
			rspamd_rs_send_final_notification(compile_cbd);
		}
		else {
			/* Workers not ready yet, notification will be sent when workers_spawned event is received */
			msg_info("compiled %d total regular expressions to the hyperscan tree, "
					 "waiting for workers to be ready before sending notification",
					 compile_cbd->total_compiled);
			ctx->loaded = TRUE;
		}
	}
}

struct rspamd_hs_helper_single_compile_cbdata {
	struct rspamd_worker *worker;
	gboolean forced;
	gboolean workers_ready;
};

static void
rspamd_rs_send_single_notification(struct rspamd_hs_helper_single_compile_cbdata *cbd)
{
	struct rspamd_worker *worker = cbd->worker;
	static struct rspamd_srv_command srv_cmd;
	struct hs_helper_ctx *ctx;

	ctx = (struct hs_helper_ctx *) worker->ctx;
	memset(&srv_cmd, 0, sizeof(srv_cmd));
	srv_cmd.type = RSPAMD_SRV_HYPERSCAN_LOADED;
	rspamd_strlcpy(srv_cmd.cmd.hs_loaded.cache_dir, ctx->hs_dir,
				   sizeof(srv_cmd.cmd.hs_loaded.cache_dir));
	srv_cmd.cmd.hs_loaded.forced = cbd->forced;
	srv_cmd.cmd.hs_loaded.scope[0] = '\0'; /* NULL scope means all scopes */

	rspamd_srv_send_command(worker,
							ctx->event_loop, &srv_cmd, -1, NULL, NULL);

	msg_info("sent hyperscan loaded notification");

	g_free(cbd);
	ev_timer_again(ctx->event_loop, &ctx->recompile_timer);
}

static void
rspamd_rs_compile_cb(unsigned int ncompiled, GError *err, void *cbd)
{
	struct rspamd_hs_helper_single_compile_cbdata *compile_cbd =
		(struct rspamd_hs_helper_single_compile_cbdata *) cbd;
	struct rspamd_worker *worker = compile_cbd->worker;
	struct hs_helper_ctx *ctx;
	struct rspamd_hs_helper_single_compile_cbdata *timer_cbd;

	ctx = (struct hs_helper_ctx *) worker->ctx;

	if (err != NULL) {
		/* Failed to compile: log and go out */
		msg_err("cannot compile Hyperscan database: %e", err);
		g_free(compile_cbd);
		return;
	}

	timer_cbd = g_malloc0(sizeof(*timer_cbd));
	timer_cbd->worker = worker;
	timer_cbd->forced = (ncompiled > 0) ? TRUE : compile_cbd->forced;
	timer_cbd->workers_ready = compile_cbd->workers_ready;

	if (timer_cbd->workers_ready) {
		/* Workers are ready, send notification immediately */
		msg_info("compiled %d regular expressions to the hyperscan tree, "
				 "send loaded notification",
				 ncompiled);
		rspamd_rs_send_single_notification(timer_cbd);
	}
	else {
		/* Workers not ready yet, notification will be sent when workers_spawned event is received */
		msg_info("compiled %d regular expressions to the hyperscan tree, "
				 "waiting for workers to be ready before sending notification",
				 ncompiled);
		ctx->loaded = TRUE;
	}

	g_free(compile_cbd);
}

static gboolean
rspamd_rs_compile(struct hs_helper_ctx *ctx, struct rspamd_worker *worker,
				  gboolean forced)
{
	msg_info("starting hyperscan compilation (forced: %s, workers_ready: %s)",
			 forced ? "yes" : "no", ctx->workers_ready ? "yes" : "no");

#if !defined(__aarch64__) && !defined(__powerpc64__)
	if (!(ctx->cfg->libs_ctx->crypto_ctx->cpu_config & CPUID_SSSE3)) {
		msg_warn("CPU doesn't have SSSE3 instructions set "
				 "required for hyperscan, disable hyperscan compilation");
		return FALSE;
	}
#endif

	if (!rspamd_hs_helper_cleanup_dir(ctx, forced)) {
		msg_warn("cannot cleanup cache dir '%s'", ctx->hs_dir);
	}

	/* Check if we have any scopes */
	unsigned int scope_count = rspamd_re_cache_count_scopes(ctx->cfg->re_cache);
	if (scope_count == 0) {
		/* No additional scopes, just default scope - use standard compilation */
		struct rspamd_hs_helper_single_compile_cbdata *single_cbd =
			g_malloc0(sizeof(*single_cbd));
		single_cbd->worker = worker;
		single_cbd->forced = forced;
		single_cbd->workers_ready = ctx->workers_ready;

		rspamd_re_cache_compile_hyperscan(ctx->cfg->re_cache,
										  ctx->hs_dir, ctx->max_time, !forced,
										  ctx->event_loop,
										  rspamd_rs_compile_cb,
										  (void *) single_cbd);
		return TRUE;
	}

	/* Count scopes and prepare compilation data */
	struct rspamd_re_cache *scope;
	unsigned int total_scopes = 0;

	/* Count valid scopes first */
	for (scope = rspamd_re_cache_scope_first(ctx->cfg->re_cache);
		 scope != NULL;
		 scope = rspamd_re_cache_scope_next(scope)) {
		const char *scope_name = rspamd_re_cache_scope_name(scope);
		const char *scope_for_check = (strcmp(scope_name, "default") == 0) ? NULL : scope_name;

		if (rspamd_re_cache_is_loaded(ctx->cfg->re_cache, scope_for_check)) {
			total_scopes++;
		}
	}

	if (total_scopes == 0) {
		/* No loaded scopes, use standard compilation for default scope */
		struct rspamd_hs_helper_single_compile_cbdata *single_cbd =
			g_malloc0(sizeof(*single_cbd));
		single_cbd->worker = worker;
		single_cbd->forced = forced;
		single_cbd->workers_ready = ctx->workers_ready;

		rspamd_re_cache_compile_hyperscan(ctx->cfg->re_cache,
										  ctx->hs_dir, ctx->max_time, !forced,
										  ctx->event_loop,
										  rspamd_rs_compile_cb,
										  (void *) single_cbd);
		return TRUE;
	}

	/* Prepare compilation callback data */
	struct rspamd_hs_helper_compile_cbdata *compile_cbd =
		g_malloc0(sizeof(*compile_cbd));
	compile_cbd->worker = worker;
	compile_cbd->ctx = ctx;
	compile_cbd->total_compiled = 0;
	compile_cbd->scopes_remaining = total_scopes;
	compile_cbd->forced = forced;
	compile_cbd->workers_ready = ctx->workers_ready;

	/* Compile each loaded scope */
	for (scope = rspamd_re_cache_scope_first(ctx->cfg->re_cache);
		 scope != NULL;
		 scope = rspamd_re_cache_scope_next(scope)) {
		const char *scope_name = rspamd_re_cache_scope_name(scope);
		const char *scope_for_compile = (strcmp(scope_name, "default") == 0) ? NULL : scope_name;

		if (rspamd_re_cache_is_loaded(ctx->cfg->re_cache, scope_for_compile)) {
			rspamd_re_cache_compile_hyperscan_scoped_single(scope, scope_for_compile,
															ctx->hs_dir, ctx->max_time, !forced,
															ctx->event_loop,
															rspamd_rs_compile_scoped_cb,
															compile_cbd);
		}
		else {
			msg_debug("skipping unloaded scope: %s", scope_name);
		}
	}
	return TRUE;
}

static gboolean
rspamd_hs_helper_reload(struct rspamd_main *rspamd_main,
						struct rspamd_worker *worker, int fd,
						int attached_fd,
						struct rspamd_control_command *cmd,
						gpointer ud)
{
	struct rspamd_control_reply rep;
	struct hs_helper_ctx *ctx = ud;

	msg_info("recompiling hyperscan expressions after receiving reload command");
	memset(&rep, 0, sizeof(rep));
	rep.type = RSPAMD_CONTROL_RECOMPILE;
	rep.reply.recompile.status = 0;

	/* We write reply before actual recompilation as it takes a lot of time */
	if (write(fd, &rep, sizeof(rep)) != sizeof(rep)) {
		msg_err("cannot write reply to the control socket: %s",
				strerror(errno));
	}

	/* Stop recompile */
	ev_timer_stop(ctx->event_loop, &ctx->recompile_timer);
	ctx->loaded = FALSE; /* Reset flag for forced recompile */
	rspamd_rs_compile(ctx, worker, TRUE);

	return TRUE;
}

static gboolean
rspamd_hs_helper_workers_spawned(struct rspamd_main *rspamd_main,
								 struct rspamd_worker *worker, int fd,
								 int attached_fd,
								 struct rspamd_control_command *cmd,
								 gpointer ud)
{
	struct rspamd_control_reply rep;
	struct hs_helper_ctx *ctx = ud;

	msg_info("received workers_spawned notification (%d workers); hyperscan compilation finished: %s",
			 cmd->cmd.workers_spawned.workers_count,
			 ctx->loaded ? "yes" : "no");

	/* Mark that workers are ready */
	ctx->workers_ready = TRUE;

	memset(&rep, 0, sizeof(rep));
	rep.type = RSPAMD_CONTROL_WORKERS_SPAWNED;
	rep.reply.workers_spawned.status = 0;

	/* Write reply */
	if (write(fd, &rep, sizeof(rep)) != sizeof(rep)) {
		msg_err("cannot write reply to the control socket: %s",
				strerror(errno));
	}

	/* If hyperscan compilation has finished but we were waiting for workers, trigger notification now */
	if (ctx->loaded) {
		static struct rspamd_srv_command srv_cmd;

		memset(&srv_cmd, 0, sizeof(srv_cmd));
		srv_cmd.type = RSPAMD_SRV_HYPERSCAN_LOADED;
		rspamd_strlcpy(srv_cmd.cmd.hs_loaded.cache_dir, ctx->hs_dir,
					   sizeof(srv_cmd.cmd.hs_loaded.cache_dir));
		srv_cmd.cmd.hs_loaded.forced = FALSE;
		srv_cmd.cmd.hs_loaded.scope[0] = '\0'; /* NULL scope means all scopes */

		rspamd_srv_send_command(worker,
								ctx->event_loop, &srv_cmd, -1, NULL, NULL);

		msg_info("sent delayed hyperscan loaded notification after workers spawned");
		ctx->loaded = FALSE; /* Reset to avoid duplicate notifications */
	}
	else {
		/* Start initial compilation now that workers are ready */
		msg_info("starting initial hyperscan compilation after workers spawned");
		if (!rspamd_rs_compile(ctx, worker, FALSE)) {
			msg_warn("initial hyperscan compilation failed or not needed");
		}
	}

	if (attached_fd != -1) {
		close(attached_fd);
	}

	return TRUE;
}

static void
rspamd_hs_helper_timer(EV_P_ ev_timer *w, int revents)
{
	struct rspamd_worker *worker = (struct rspamd_worker *) w->data;
	struct hs_helper_ctx *ctx;
	double tim;

	ctx = worker->ctx;
	tim = rspamd_time_jitter(ctx->recompile_time, 0);
	w->repeat = tim;

	msg_info("periodic recompilation timer triggered (workers_ready: %s)",
			 ctx->workers_ready ? "yes" : "no");
	rspamd_rs_compile(ctx, worker, FALSE);
}

static void
start_hs_helper(struct rspamd_worker *worker)
{
	struct hs_helper_ctx *ctx = worker->ctx;
	double tim;

	g_assert(rspamd_worker_check_context(worker->ctx, rspamd_hs_helper_magic));
	ctx->cfg = worker->srv->cfg;

	if (ctx->hs_dir == NULL) {
		ctx->hs_dir = ctx->cfg->hs_cache_dir;
	}
	if (ctx->hs_dir == NULL) {
		ctx->hs_dir = RSPAMD_DBDIR "/";
	}

	msg_info("hs_helper starting: cache_dir=%s, recompile_time=%.1f, workers_ready=%s",
			 ctx->hs_dir, ctx->recompile_time, ctx->workers_ready ? "yes" : "no");

	ctx->event_loop = rspamd_prepare_worker(worker,
											"hs_helper",
											NULL);

	rspamd_control_worker_add_cmd_handler(worker, RSPAMD_CONTROL_RECOMPILE,
										  rspamd_hs_helper_reload, ctx);
	rspamd_control_worker_add_cmd_handler(worker, RSPAMD_CONTROL_WORKERS_SPAWNED,
										  rspamd_hs_helper_workers_spawned, ctx);

	ctx->recompile_timer.data = worker;
	tim = rspamd_time_jitter(ctx->recompile_time, 0);
	msg_info("setting up recompile timer for %.1f seconds", tim);
	ev_timer_init(&ctx->recompile_timer, rspamd_hs_helper_timer, tim, 0.0);
	ev_timer_start(ctx->event_loop, &ctx->recompile_timer);

	msg_info("hs_helper starting event loop");
	ev_loop(ctx->event_loop, 0);
	rspamd_worker_block_signals();

	rspamd_log_close(worker->srv->logger);
	REF_RELEASE(ctx->cfg);
	rspamd_unset_crash_handler(worker->srv);

	exit(EXIT_SUCCESS);
}
