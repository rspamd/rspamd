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
#include "rspamd.h"
#include "lua/lua_common.h"
#include "worker_util.h"
#include "unix-std.h"
#include "utlist.h"
#include "ottery.h"
#include "rspamd_control.h"
#include "libserver/maps/map.h"
#include "libserver/maps/map_private.h"
#include "libserver/http/http_private.h"
#include "libserver/http/http_router.h"
#include "libutil/rrd.h"

/* sys/resource.h */
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
/* pwd and grp */
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif
#include "zlib.h"

#ifdef WITH_LIBUNWIND
#define UNW_LOCAL_ONLY 1
#include <libunwind.h>
#define UNWIND_BACKTRACE_DEPTH 256
#endif

#ifdef HAVE_UCONTEXT_H
#include <ucontext.h>
#elif defined(HAVE_SYS_UCONTEXT_H)
#include <sys/ucontext.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include "contrib/libev/ev.h"
#include "libstat/stat_api.h"

/* Forward declaration */
static void rspamd_worker_heartbeat_start (struct rspamd_worker *,
		struct ev_loop *);

static void rspamd_worker_ignore_signal (struct rspamd_worker_signal_handler *);
/**
 * Return worker's control structure by its type
 * @param type
 * @return worker's control structure or NULL
 */
worker_t *
rspamd_get_worker_by_type (struct rspamd_config *cfg, GQuark type)
{
	worker_t **pwrk;

	pwrk = cfg->compiled_workers;
	while (pwrk && *pwrk) {
		if (rspamd_check_worker (cfg, *pwrk)) {
			if (g_quark_from_string ((*pwrk)->name) == type) {
				return *pwrk;
			}
		}

		pwrk++;
	}

	return NULL;
}

static void
rspamd_worker_check_finished (EV_P_ ev_timer *w, int revents)
{
	int *pnchecks = (int *)w->data;

	if (*pnchecks > SOFT_SHUTDOWN_TIME * 10) {
		msg_warn ("terminating worker before finishing of terminate handlers");
		ev_break (EV_A_ EVBREAK_ONE);
	}
	else {
		int refcount = ev_active_cnt (EV_A);

		if (refcount == 1) {
			ev_break (EV_A_ EVBREAK_ONE);
		}
		else {
			ev_timer_again (EV_A_ w);
		}
	}
}

static gboolean
rspamd_worker_finalize (gpointer user_data)
{
	struct rspamd_task *task = user_data;

	if (!(task->flags & RSPAMD_TASK_FLAG_PROCESSING)) {
		msg_info_task ("finishing actions has been processed, terminating");
		/* ev_break (task->event_loop, EVBREAK_ALL); */
		task->worker->state = rspamd_worker_wanna_die;
		rspamd_session_destroy (task->s);

		return TRUE;
	}

	return FALSE;
}

gboolean
rspamd_worker_call_finish_handlers (struct rspamd_worker *worker)
{
	struct rspamd_task *task;
	struct rspamd_config *cfg = worker->srv->cfg;
	struct rspamd_abstract_worker_ctx *ctx;
	struct rspamd_config_cfg_lua_script *sc;

	if (cfg->on_term_scripts) {
		ctx = (struct rspamd_abstract_worker_ctx *)worker->ctx;
		/* Create a fake task object for async events */
		task = rspamd_task_new (worker, cfg, NULL, NULL, ctx->event_loop, FALSE);
		task->resolver = ctx->resolver;
		task->flags |= RSPAMD_TASK_FLAG_PROCESSING;
		task->s = rspamd_session_create (task->task_pool,
				rspamd_worker_finalize,
				NULL,
				(event_finalizer_t) rspamd_task_free,
				task);

		DL_FOREACH (cfg->on_term_scripts, sc) {
			lua_call_finish_script (sc, task);
		}

		task->flags &= ~RSPAMD_TASK_FLAG_PROCESSING;

		if (rspamd_session_pending (task->s)) {
			return TRUE;
		}
	}

	return FALSE;
}

static void
rspamd_worker_terminate_handlers (struct rspamd_worker *w)
{
	if (w->nconns == 0 &&
		(!(w->flags & RSPAMD_WORKER_SCANNER) || w->srv->cfg->on_term_scripts == NULL)) {
		/*
		 * We are here either:
		 * - No active connections are represented
		 * - No term scripts are registered
		 * - Worker is not a scanner, so it can die safely
		 */
		w->state = rspamd_worker_wanna_die;
	}
	else {
		if (w->nconns > 0) {
			/*
			 * Wait until all connections are terminated
			 */
			w->state = rspamd_worker_wait_connections;
		}
		else {
			/*
			 * Start finish scripts
			 */
			if (w->state != rspamd_worker_wait_final_scripts) {
				w->state = rspamd_worker_wait_final_scripts;

				if ((w->flags & RSPAMD_WORKER_SCANNER) &&
					rspamd_worker_call_finish_handlers (w)) {
					msg_info ("performing async finishing actions");
					w->state = rspamd_worker_wait_final_scripts;
				}
				else {
					/*
					 * We are done now
					 */
					msg_info ("no async finishing actions, terminating");
					w->state = rspamd_worker_wanna_die;
				}
			}
		}
	}
}

static void
rspamd_worker_on_delayed_shutdown (EV_P_ ev_timer *w, int revents)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)w->data;

	worker->state = rspamd_worker_wanna_die;
	ev_timer_stop (EV_A_ w);
	ev_break (loop, EVBREAK_ALL);
}

static void
rspamd_worker_shutdown_check (EV_P_ ev_timer *w, int revents)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)w->data;

	if (worker->state != rspamd_worker_wanna_die) {
		rspamd_worker_terminate_handlers (worker);

		if (worker->state == rspamd_worker_wanna_die) {
			/* We are done, kill event loop */
			ev_timer_stop (EV_A_ w);
			ev_break (EV_A_ EVBREAK_ALL);
		}
		else {
			/* Try again later */
			ev_timer_again (EV_A_ w);
		}
	}
	else {
		ev_timer_stop (EV_A_ w);
		ev_break (EV_A_ EVBREAK_ALL);
	}
}

/*
 * Config reload is designed by sending sigusr2 to active workers and pending shutdown of them
 */
static gboolean
rspamd_worker_usr2_handler (struct rspamd_worker_signal_handler *sigh, void *arg)
{
	/* Do not accept new connections, preparing to end worker's process */
	if (sigh->worker->state == rspamd_worker_state_running) {
		static ev_timer shutdown_ev, shutdown_check_ev;
		ev_tstamp shutdown_ts;

		if (sigh->worker->flags & RSPAMD_WORKER_NO_TERMINATE_DELAY) {
			shutdown_ts = 0.0;
		}
		else {
			shutdown_ts = MAX (SOFT_SHUTDOWN_TIME,
					sigh->worker->srv->cfg->task_timeout * 2.0);
		}

		rspamd_worker_ignore_signal (sigh);
		sigh->worker->state = rspamd_worker_state_terminating;

		rspamd_default_log_function (G_LOG_LEVEL_INFO,
				sigh->worker->srv->server_pool->tag.tagname,
				sigh->worker->srv->server_pool->tag.uid,
				G_STRFUNC,
				"worker's shutdown is pending in %.2f sec",
				shutdown_ts);

		/* Soft shutdown timer */
		shutdown_ev.data = sigh->worker;
		ev_timer_init (&shutdown_ev, rspamd_worker_on_delayed_shutdown,
				shutdown_ts, 0.0);
		ev_timer_start (sigh->event_loop, &shutdown_ev);

		if (!(sigh->worker->flags & RSPAMD_WORKER_NO_TERMINATE_DELAY)) {
			/* This timer checks if we are ready to die and is called frequently */
			shutdown_check_ev.data = sigh->worker;
			ev_timer_init (&shutdown_check_ev, rspamd_worker_shutdown_check,
					0.5, 0.5);
			ev_timer_start (sigh->event_loop, &shutdown_check_ev);
		}

		rspamd_worker_stop_accept (sigh->worker);
	}

	/* No more signals */
	return FALSE;
}

/*
 * Reopen log is designed by sending sigusr1 to active workers and pending shutdown of them
 */
static gboolean
rspamd_worker_usr1_handler (struct rspamd_worker_signal_handler *sigh, void *arg)
{
	struct rspamd_main *rspamd_main = sigh->worker->srv;

	rspamd_log_reopen (sigh->worker->srv->logger, rspamd_main->cfg, -1, -1);
	msg_info_main ("logging reinitialised");

	/* Get more signals */
	return TRUE;
}

static gboolean
rspamd_worker_term_handler (struct rspamd_worker_signal_handler *sigh, void *arg)
{
	if (sigh->worker->state == rspamd_worker_state_running) {
		static ev_timer shutdown_ev, shutdown_check_ev;
		ev_tstamp shutdown_ts;

		if (sigh->worker->flags & RSPAMD_WORKER_NO_TERMINATE_DELAY) {
			shutdown_ts = 0.0;
		}
		else {
			shutdown_ts = MAX (SOFT_SHUTDOWN_TIME,
					sigh->worker->srv->cfg->task_timeout * 2.0);
		}

		rspamd_worker_ignore_signal (sigh);
		sigh->worker->state = rspamd_worker_state_terminating;
		rspamd_default_log_function (G_LOG_LEVEL_INFO,
				sigh->worker->srv->server_pool->tag.tagname,
				sigh->worker->srv->server_pool->tag.uid,
				G_STRFUNC,
				"terminating after receiving signal %s",
				g_strsignal (sigh->signo));

		rspamd_worker_stop_accept (sigh->worker);
		rspamd_worker_terminate_handlers (sigh->worker);

		/* Check if we are ready to die */
		if (sigh->worker->state != rspamd_worker_wanna_die) {
			/* This timer is called when we have no choices but to die */
			shutdown_ev.data = sigh->worker;
			ev_timer_init (&shutdown_ev, rspamd_worker_on_delayed_shutdown,
					shutdown_ts, 0.0);
			ev_timer_start (sigh->event_loop, &shutdown_ev);

			if (!(sigh->worker->flags & RSPAMD_WORKER_NO_TERMINATE_DELAY)) {
				/* This timer checks if we are ready to die and is called frequently */
				shutdown_check_ev.data = sigh->worker;
				ev_timer_init (&shutdown_check_ev, rspamd_worker_shutdown_check,
						0.5, 0.5);
				ev_timer_start (sigh->event_loop, &shutdown_check_ev);
			}
		}
		else {
			/* Flag to die has been already set */
			ev_break (sigh->event_loop, EVBREAK_ALL);
		}
	}

	/* Stop reacting on signals */
	return FALSE;
}

static void
rspamd_worker_signal_handle (EV_P_ ev_signal *w, int revents)
{
	struct rspamd_worker_signal_handler *sigh =
			(struct rspamd_worker_signal_handler *)w->data;
	struct rspamd_worker_signal_handler_elt *cb, *cbtmp;

	/* Call all signal handlers registered */
	DL_FOREACH_SAFE (sigh->cb, cb, cbtmp) {
		if (!cb->handler (sigh, cb->handler_data)) {
			DL_DELETE (sigh->cb, cb);
			g_free (cb);
		}
	}
}

static void
rspamd_worker_ignore_signal (struct rspamd_worker_signal_handler *sigh)
{
	sigset_t set;

	ev_signal_stop (sigh->event_loop, &sigh->ev_sig);
	sigemptyset (&set);
	sigaddset (&set, sigh->signo);
	sigprocmask (SIG_BLOCK, &set, NULL);
}

static void
rspamd_worker_default_signal (int signo)
{
	struct sigaction sig;

	sigemptyset (&sig.sa_mask);
	sigaddset (&sig.sa_mask, signo);
	sig.sa_handler = SIG_DFL;
	sig.sa_flags = 0;
	sigaction (signo, &sig, NULL);
}

static void
rspamd_sigh_free (void *p)
{
	struct rspamd_worker_signal_handler *sigh = p;
	struct rspamd_worker_signal_handler_elt *cb, *tmp;

	DL_FOREACH_SAFE (sigh->cb, cb, tmp) {
		DL_DELETE (sigh->cb, cb);
		g_free (cb);
	}

	ev_signal_stop (sigh->event_loop, &sigh->ev_sig);
	rspamd_worker_default_signal (sigh->signo);
	g_free (sigh);
}

void
rspamd_worker_set_signal_handler (int signo, struct rspamd_worker *worker,
		struct ev_loop *event_loop,
		rspamd_worker_signal_cb_t handler,
		void *handler_data)
{
	struct rspamd_worker_signal_handler *sigh;
	struct rspamd_worker_signal_handler_elt *cb;

	sigh = g_hash_table_lookup (worker->signal_events, GINT_TO_POINTER (signo));

	if (sigh == NULL) {
		sigh = g_malloc0 (sizeof (*sigh));
		sigh->signo = signo;
		sigh->worker = worker;
		sigh->event_loop = event_loop;
		sigh->enabled = TRUE;

		sigh->ev_sig.data = sigh;
		ev_signal_init (&sigh->ev_sig, rspamd_worker_signal_handle, signo);
		ev_signal_start (event_loop, &sigh->ev_sig);

		g_hash_table_insert (worker->signal_events,
				GINT_TO_POINTER (signo),
				sigh);
	}

	cb = g_malloc0 (sizeof (*cb));
	cb->handler = handler;
	cb->handler_data = handler_data;
	DL_APPEND (sigh->cb, cb);
}

void
rspamd_worker_init_signals (struct rspamd_worker *worker,
		struct ev_loop *event_loop)
{
	/* A set of terminating signals */
	rspamd_worker_set_signal_handler (SIGTERM, worker, event_loop,
			rspamd_worker_term_handler, NULL);
	rspamd_worker_set_signal_handler (SIGINT, worker, event_loop,
			rspamd_worker_term_handler, NULL);
	rspamd_worker_set_signal_handler (SIGHUP, worker, event_loop,
			rspamd_worker_term_handler, NULL);

	/* Special purpose signals */
	rspamd_worker_set_signal_handler (SIGUSR1, worker, event_loop,
			rspamd_worker_usr1_handler, NULL);
	rspamd_worker_set_signal_handler (SIGUSR2, worker, event_loop,
			rspamd_worker_usr2_handler, NULL);
}


struct ev_loop *
rspamd_prepare_worker (struct rspamd_worker *worker, const char *name,
					   rspamd_accept_handler hdl)
{
	struct ev_loop *event_loop;
	GList *cur;
	struct rspamd_worker_listen_socket *ls;
	struct rspamd_worker_accept_event *accept_ev;

	worker->signal_events = g_hash_table_new_full (g_direct_hash, g_direct_equal,
			NULL, rspamd_sigh_free);

	event_loop = ev_loop_new (rspamd_config_ev_backend_get (worker->srv->cfg));

	worker->srv->event_loop = event_loop;

	rspamd_worker_init_signals (worker, event_loop);
	rspamd_control_worker_add_default_cmd_handlers (worker, event_loop);
	rspamd_worker_heartbeat_start (worker, event_loop);
	rspamd_redis_pool_config (worker->srv->cfg->redis_pool,
			worker->srv->cfg, event_loop);

	/* Accept all sockets */
	if (hdl) {
		cur = worker->cf->listen_socks;

		while (cur) {
			ls = cur->data;

			if (ls->fd != -1) {
				accept_ev = g_malloc0 (sizeof (*accept_ev));
				accept_ev->event_loop = event_loop;
				accept_ev->accept_ev.data = worker;
				ev_io_init (&accept_ev->accept_ev, hdl, ls->fd, EV_READ);
				ev_io_start (event_loop, &accept_ev->accept_ev);

				DL_APPEND (worker->accept_events, accept_ev);
			}

			cur = g_list_next (cur);
		}
	}

	return event_loop;
}

void
rspamd_worker_stop_accept (struct rspamd_worker *worker)
{
	struct rspamd_worker_accept_event *cur, *tmp;

	/* Remove all events */
	DL_FOREACH_SAFE (worker->accept_events, cur, tmp) {

		if (ev_can_stop (&cur->accept_ev)) {
			ev_io_stop (cur->event_loop, &cur->accept_ev);
		}


		if (ev_can_stop (&cur->throttling_ev)) {
			ev_timer_stop (cur->event_loop, &cur->throttling_ev);
		}

		g_free (cur);
	}

	/* XXX: we need to do it much later */
#if 0
	g_hash_table_iter_init (&it, worker->signal_events);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		sigh = (struct rspamd_worker_signal_handler *)v;
		g_hash_table_iter_steal (&it);

		if (sigh->enabled) {
			event_del (&sigh->ev);
		}

		g_free (sigh);
	}

	g_hash_table_unref (worker->signal_events);
#endif
}

static rspamd_fstring_t *
rspamd_controller_maybe_compress (struct rspamd_http_connection_entry *entry,
		rspamd_fstring_t *buf, struct rspamd_http_message *msg)
{
	if (entry->support_gzip) {
		if (rspamd_fstring_gzip (&buf)) {
			rspamd_http_message_add_header (msg, "Content-Encoding", "gzip");
		}
	}

	return buf;
}

void
rspamd_controller_send_error (struct rspamd_http_connection_entry *entry,
	gint code, const gchar *error_msg, ...)
{
	struct rspamd_http_message *msg;
	va_list args;
	rspamd_fstring_t *reply;

	msg = rspamd_http_new_message (HTTP_RESPONSE);

	va_start (args, error_msg);
	msg->status = rspamd_fstring_new ();
	rspamd_vprintf_fstring (&msg->status, error_msg, args);
	va_end (args);

	msg->date = time (NULL);
	msg->code = code;
	reply = rspamd_fstring_sized_new (msg->status->len + 16);
	rspamd_printf_fstring (&reply, "{\"error\":\"%V\"}", msg->status);
	rspamd_http_message_set_body_from_fstring_steal (msg,
			rspamd_controller_maybe_compress (entry, reply, msg));
	rspamd_http_connection_reset (entry->conn);
	rspamd_http_router_insert_headers (entry->rt, msg);
	rspamd_http_connection_write_message (entry->conn,
		msg,
		NULL,
		"application/json",
		entry,
		entry->rt->timeout);
	entry->is_reply = TRUE;
}

void
rspamd_controller_send_openmetrics (struct rspamd_http_connection_entry *entry,
									rspamd_fstring_t *str)
{
	struct rspamd_http_message *msg;

	msg = rspamd_http_new_message (HTTP_RESPONSE);
	msg->date = time (NULL);
	msg->code = 200;
	msg->status = rspamd_fstring_new_init ("OK", 2);

	rspamd_http_message_set_body_from_fstring_steal (msg,
			rspamd_controller_maybe_compress (entry, str, msg));
	rspamd_http_connection_reset (entry->conn);
	rspamd_http_router_insert_headers (entry->rt, msg);
	rspamd_http_connection_write_message (entry->conn,
		msg,
		NULL,
		"application/openmetrics-text; version=1.0.0; charset=utf-8",
		entry,
		entry->rt->timeout);
	entry->is_reply = TRUE;
}

void
rspamd_controller_send_string (struct rspamd_http_connection_entry *entry,
	const gchar *str)
{
	struct rspamd_http_message *msg;
	rspamd_fstring_t *reply;

	msg = rspamd_http_new_message (HTTP_RESPONSE);
	msg->date = time (NULL);
	msg->code = 200;
	msg->status = rspamd_fstring_new_init ("OK", 2);

	if (str) {
		reply = rspamd_fstring_new_init (str, strlen (str));
	}
	else {
		reply = rspamd_fstring_new_init ("null", 4);
	}

	rspamd_http_message_set_body_from_fstring_steal (msg,
			rspamd_controller_maybe_compress (entry, reply, msg));
	rspamd_http_connection_reset (entry->conn);
	rspamd_http_router_insert_headers (entry->rt, msg);
	rspamd_http_connection_write_message (entry->conn,
		msg,
		NULL,
		"application/json",
		entry,
		entry->rt->timeout);
	entry->is_reply = TRUE;
}

void
rspamd_controller_send_ucl (struct rspamd_http_connection_entry *entry,
	ucl_object_t *obj)
{
	struct rspamd_http_message *msg;
	rspamd_fstring_t *reply;

	msg = rspamd_http_new_message (HTTP_RESPONSE);
	msg->date = time (NULL);
	msg->code = 200;
	msg->status = rspamd_fstring_new_init ("OK", 2);
	reply = rspamd_fstring_sized_new (BUFSIZ);
	rspamd_ucl_emit_fstring (obj, UCL_EMIT_JSON_COMPACT, &reply);
	rspamd_http_message_set_body_from_fstring_steal (msg,
			rspamd_controller_maybe_compress (entry, reply, msg));
	rspamd_http_connection_reset (entry->conn);
	rspamd_http_router_insert_headers (entry->rt, msg);
	rspamd_http_connection_write_message (entry->conn,
		msg,
		NULL,
		"application/json",
		entry,
		entry->rt->timeout);
	entry->is_reply = TRUE;
}

static void
rspamd_worker_drop_priv (struct rspamd_main *rspamd_main)
{
	if (rspamd_main->is_privilleged) {
		if (setgid (rspamd_main->workers_gid) == -1) {
			msg_err_main ("cannot setgid to %d (%s), aborting",
					(gint) rspamd_main->workers_gid,
					strerror (errno));
			exit (-errno);
		}

		if (rspamd_main->cfg->rspamd_user &&
				initgroups (rspamd_main->cfg->rspamd_user,
						rspamd_main->workers_gid) == -1) {
			msg_err_main ("initgroups failed (%s), aborting", strerror (errno));
			exit (-errno);
		}

		if (setuid (rspamd_main->workers_uid) == -1) {
			msg_err_main ("cannot setuid to %d (%s), aborting",
					(gint) rspamd_main->workers_uid,
					strerror (errno));
			exit (-errno);
		}
	}
}

static void
rspamd_worker_set_limits (struct rspamd_main *rspamd_main,
		struct rspamd_worker_conf *cf)
{
	struct rlimit rlmt;

	if (cf->rlimit_nofile != 0) {
		rlmt.rlim_cur = (rlim_t) cf->rlimit_nofile;
		rlmt.rlim_max = (rlim_t) cf->rlimit_nofile;

		if (setrlimit (RLIMIT_NOFILE, &rlmt) == -1) {
			msg_warn_main ("cannot set files rlimit: %L, %s",
					cf->rlimit_nofile,
					strerror (errno));
		}

		memset (&rlmt, 0, sizeof (rlmt));

		if (getrlimit (RLIMIT_NOFILE, &rlmt) == -1) {
			msg_warn_main ("cannot get max files rlimit: %HL, %s",
					cf->rlimit_maxcore,
					strerror (errno));
		}
		else {
			msg_info_main ("set max file descriptors limit: %HL cur and %HL max",
					(guint64) rlmt.rlim_cur,
					(guint64) rlmt.rlim_max);
		}
	}
	else {
		/* Just report */
		if (getrlimit (RLIMIT_NOFILE, &rlmt) == -1) {
			msg_warn_main ("cannot get max files rlimit: %HL, %s",
					cf->rlimit_maxcore,
					strerror (errno));
		}
		else {
			msg_info_main ("use system max file descriptors limit: %HL cur and %HL max",
					(guint64) rlmt.rlim_cur,
					(guint64) rlmt.rlim_max);
		}
	}

	if (rspamd_main->cores_throttling) {
		msg_info_main ("disable core files for the new worker as limits are reached");
		rlmt.rlim_cur = 0;
		rlmt.rlim_max = 0;

		if (setrlimit (RLIMIT_CORE, &rlmt) == -1) {
			msg_warn_main ("cannot disable core dumps: error when setting limits: %s",
					strerror (errno));
		}
	}
	else {
		if (cf->rlimit_maxcore != 0) {
			rlmt.rlim_cur = (rlim_t) cf->rlimit_maxcore;
			rlmt.rlim_max = (rlim_t) cf->rlimit_maxcore;

			if (setrlimit (RLIMIT_CORE, &rlmt) == -1) {
				msg_warn_main ("cannot set max core size limit: %HL, %s",
						cf->rlimit_maxcore,
						strerror (errno));
			}

			/* Ensure that we did it */
			memset (&rlmt, 0, sizeof (rlmt));

			if (getrlimit (RLIMIT_CORE, &rlmt) == -1) {
				msg_warn_main ("cannot get max core size rlimit: %HL, %s",
						cf->rlimit_maxcore,
						strerror (errno));
			}
			else {
				if (rlmt.rlim_cur != cf->rlimit_maxcore ||
					rlmt.rlim_max != cf->rlimit_maxcore) {
					msg_warn_main ("setting of core file limits was unsuccessful: "
								   "%HL was wanted, "
								   "but we have %HL cur and %HL max",
							cf->rlimit_maxcore,
							(guint64) rlmt.rlim_cur,
							(guint64) rlmt.rlim_max);
				}
				else {
					msg_info_main ("set max core size limit: %HL cur and %HL max",
							(guint64) rlmt.rlim_cur,
							(guint64) rlmt.rlim_max);
				}
			}
		}
		else {
			/* Just report */
			if (getrlimit (RLIMIT_CORE, &rlmt) == -1) {
				msg_warn_main ("cannot get max core size limit: %HL, %s",
						cf->rlimit_maxcore,
						strerror (errno));
			}
			else {
				msg_info_main ("use system max core size limit: %HL cur and %HL max",
						(guint64) rlmt.rlim_cur,
						(guint64) rlmt.rlim_max);
			}
		}
	}
}

static void
rspamd_worker_on_term (EV_P_ ev_child *w, int revents)
{
	struct rspamd_worker *wrk = (struct rspamd_worker *)w->data;

	if (wrk->ppid == getpid ()) {
		if (wrk->term_handler) {
			wrk->term_handler (EV_A_ w, wrk->srv, wrk);
		}
		else {
			rspamd_check_termination_clause (wrk->srv, wrk, w->rstatus);
		}
	}
	else {
		/* Ignore SIGCHLD for not our children... */
	}
}

static void
rspamd_worker_heartbeat_cb (EV_P_ ev_timer *w, int revents)
{
	struct rspamd_worker *wrk = (struct rspamd_worker *)w->data;
	struct rspamd_srv_command cmd;

	memset (&cmd, 0, sizeof (cmd));
	cmd.type = RSPAMD_SRV_HEARTBEAT;
	rspamd_srv_send_command (wrk, EV_A, &cmd, -1, NULL, NULL);
}

static void
rspamd_worker_heartbeat_start (struct rspamd_worker *wrk, struct ev_loop *event_loop)
{
	wrk->hb.heartbeat_ev.data = (void *)wrk;
	ev_timer_init (&wrk->hb.heartbeat_ev, rspamd_worker_heartbeat_cb,
			0.0, wrk->srv->cfg->heartbeat_interval);
	ev_timer_start (event_loop, &wrk->hb.heartbeat_ev);
}

static void
rspamd_main_heartbeat_cb (EV_P_ ev_timer *w, int revents)
{
	struct rspamd_worker *wrk = (struct rspamd_worker *)w->data;
	gdouble time_from_last = ev_time ();
	struct rspamd_main *rspamd_main;
	static struct rspamd_control_command cmd;
	struct tm tm;
	gchar timebuf[64];
	gchar usec_buf[16];
	gint r;

	time_from_last -= wrk->hb.last_event;
	rspamd_main = wrk->srv;

	if (wrk->hb.last_event > 0 &&
		time_from_last > 0 &&
		time_from_last >= rspamd_main->cfg->heartbeat_interval * 2) {

		rspamd_localtime (wrk->hb.last_event, &tm);
		r = strftime (timebuf, sizeof (timebuf), "%F %H:%M:%S", &tm);
		rspamd_snprintf (usec_buf, sizeof (usec_buf), "%.5f",
				wrk->hb.last_event - (gdouble)(time_t)wrk->hb.last_event);
		rspamd_snprintf (timebuf + r, sizeof (timebuf) - r,
				"%s", usec_buf + 1);

		if (wrk->hb.nbeats > 0) {
			/* First time lost event */
			cmd.type = RSPAMD_CONTROL_CHILD_CHANGE;
			cmd.cmd.child_change.what = rspamd_child_offline;
			cmd.cmd.child_change.pid = wrk->pid;
			rspamd_control_broadcast_srv_cmd (rspamd_main, &cmd, wrk->pid);
			msg_warn_main ("lost heartbeat from worker type %s with pid %P, "
				  "last beat on: %s (%L beats received previously)",
					g_quark_to_string (wrk->type), wrk->pid,
					timebuf,
					wrk->hb.nbeats);
			wrk->hb.nbeats = -1;
			/* TODO: send notify about worker problem */
		}
		else {
			wrk->hb.nbeats --;
			msg_warn_main ("lost %L heartbeat from worker type %s with pid %P, "
						   "last beat on: %s",
					-(wrk->hb.nbeats),
					g_quark_to_string (wrk->type),
					wrk->pid,
					timebuf);

			if (rspamd_main->cfg->heartbeats_loss_max > 0 &&
				-(wrk->hb.nbeats) >= rspamd_main->cfg->heartbeats_loss_max) {


				if (-(wrk->hb.nbeats) > rspamd_main->cfg->heartbeats_loss_max + 1) {
					msg_err_main ("force kill worker type %s with pid %P, "
								  "last beat on: %s; %L heartbeat lost",
							g_quark_to_string (wrk->type),
							wrk->pid,
							timebuf,
							-(wrk->hb.nbeats));
					kill (wrk->pid, SIGKILL);
				}
				else {
					msg_err_main ("terminate worker type %s with pid %P, "
								  "last beat on: %s; %L heartbeat lost",
							g_quark_to_string (wrk->type),
							wrk->pid,
							timebuf,
							-(wrk->hb.nbeats));
					kill (wrk->pid, SIGTERM);
				}

			}
		}
	}
	else if (wrk->hb.nbeats < 0) {
		rspamd_localtime (wrk->hb.last_event, &tm);
		r = strftime (timebuf, sizeof (timebuf), "%F %H:%M:%S", &tm);
		rspamd_snprintf (usec_buf, sizeof (usec_buf), "%.5f",
				wrk->hb.last_event - (gdouble)(time_t)wrk->hb.last_event);
		rspamd_snprintf (timebuf + r, sizeof (timebuf) - r,
				"%s", usec_buf + 1);

		cmd.type = RSPAMD_CONTROL_CHILD_CHANGE;
		cmd.cmd.child_change.what = rspamd_child_online;
		cmd.cmd.child_change.pid = wrk->pid;
		rspamd_control_broadcast_srv_cmd (rspamd_main, &cmd, wrk->pid);
		msg_info_main ("received heartbeat from worker type %s with pid %P, "
					   "last beat on: %s (%L beats lost previously)",
				g_quark_to_string (wrk->type), wrk->pid,
				timebuf,
				-(wrk->hb.nbeats));
		wrk->hb.nbeats = 1;
		/* TODO: send notify about worker restoration */
	}
}

static void
rspamd_main_heartbeat_start (struct rspamd_worker *wrk, struct ev_loop *event_loop)
{
	wrk->hb.heartbeat_ev.data = (void *)wrk;
	ev_timer_init (&wrk->hb.heartbeat_ev, rspamd_main_heartbeat_cb,
			0.0, wrk->srv->cfg->heartbeat_interval * 2);
	ev_timer_start (event_loop, &wrk->hb.heartbeat_ev);
}

static bool
rspamd_maybe_reuseport_socket (struct rspamd_worker_listen_socket *ls)
{
	gint nfd = -1;

	if (ls->is_systemd) {
		/* No need to reuseport */
		return true;
	}

	if (ls->fd != -1 && rspamd_inet_address_get_af (ls->addr) == AF_UNIX) {
		/* Just try listen */

		if (listen (ls->fd, -1) == -1) {
			return false;
		}

		return true;
	}

#if defined(SO_REUSEPORT) && defined(SO_REUSEADDR) && defined(LINUX)

	if (ls->type == RSPAMD_WORKER_SOCKET_UDP) {
		nfd = rspamd_inet_address_listen (ls->addr,
				(ls->type == RSPAMD_WORKER_SOCKET_UDP ? SOCK_DGRAM : SOCK_STREAM),
				RSPAMD_INET_ADDRESS_LISTEN_ASYNC|RSPAMD_INET_ADDRESS_LISTEN_REUSEPORT,
				-1);

		if (nfd == -1) {
			msg_warn ("cannot create reuseport listen socket for %d: %s",
					ls->fd, strerror (errno));
			nfd = ls->fd;
		}
		else {
			if (ls->fd != -1) {
				close (ls->fd);
			}
			ls->fd = nfd;
			nfd = -1;
		}
	}
	else {
		/*
		 * Reuseport is broken with the current architecture, so it is easier not
		 * to use it at all
		 */
		nfd = ls->fd;
	}
#else
	nfd = ls->fd;
#endif

#if 0
	/* This needed merely if we have reuseport for tcp, but for now it is disabled */
	/* This means that we have an fd with no listening enabled */
	if (nfd != -1) {
		if (ls->type == RSPAMD_WORKER_SOCKET_TCP) {
			if (listen (nfd, -1) == -1) {
				return false;
			}
		}
	}
#endif

	return true;
}

/**
 * Handles worker after fork returned zero
 * @param wrk
 * @param rspamd_main
 * @param cf
 * @param listen_sockets
 */
static void __attribute__((noreturn))
rspamd_handle_child_fork (struct rspamd_worker *wrk,
						  struct rspamd_main *rspamd_main,
						  struct rspamd_worker_conf *cf,
						  GHashTable *listen_sockets)
{
	gint rc;
	struct rlimit rlim;

	/* Update pid for logging */
	rspamd_log_on_fork (cf->type, rspamd_main->cfg, rspamd_main->logger);
	wrk->pid = getpid ();

	/* Init PRNG after fork */
	rc = ottery_init (rspamd_main->cfg->libs_ctx->ottery_cfg);
	if (rc != OTTERY_ERR_NONE) {
		msg_err_main ("cannot initialize PRNG: %d", rc);
		abort ();
	}

	rspamd_random_seed_fast ();
#ifdef HAVE_EVUTIL_RNG_INIT
	evutil_secure_rng_init ();
#endif

	/*
	 * Libev stores all signals in a global table, so
	 * previous handlers must be explicitly detached and forgotten
	 * before starting a new loop
	 */
	ev_signal_stop (rspamd_main->event_loop, &rspamd_main->int_ev);
	ev_signal_stop (rspamd_main->event_loop, &rspamd_main->term_ev);
	ev_signal_stop (rspamd_main->event_loop, &rspamd_main->hup_ev);
	ev_signal_stop (rspamd_main->event_loop, &rspamd_main->usr1_ev);
	/* Remove the inherited event base */
	ev_loop_destroy (rspamd_main->event_loop);
	rspamd_main->event_loop = NULL;

	/* Close unused sockets */
	GHashTableIter it;
	gpointer k, v;


	g_hash_table_iter_init (&it, listen_sockets);

	/*
	 * Close listen sockets of not our process (inherited from other forks)
	 */
	while (g_hash_table_iter_next (&it, &k, &v)) {
		GList *elt = (GList *)v;
		GList *our = cf->listen_socks;

		if (g_list_position (our, elt) == -1) {
			GList *cur = elt;

			while (cur) {
				struct rspamd_worker_listen_socket *ls =
						(struct rspamd_worker_listen_socket *)cur->data;

				if (ls->fd != -1 && close (ls->fd) == -1) {
					msg_err ("cannot close fd %d (addr = %s): %s",
							ls->fd,
							rspamd_inet_address_to_string_pretty (ls->addr),
							strerror (errno));
				}

				ls->fd = -1;

				cur = g_list_next (cur);
			}
		}
	}

	/* Reuseport before dropping privs */
	GList *cur = cf->listen_socks;

	while (cur) {
		struct rspamd_worker_listen_socket *ls =
				(struct rspamd_worker_listen_socket *)cur->data;

		if (!rspamd_maybe_reuseport_socket (ls)) {
			msg_err ("cannot listen on socket %s: %s",
					rspamd_inet_address_to_string_pretty (ls->addr),
					strerror (errno));
		}

		cur = g_list_next (cur);
	}

	/* Drop privileges */
	rspamd_worker_drop_priv (rspamd_main);
	/* Set limits */
	rspamd_worker_set_limits (rspamd_main, cf);
	/* Re-set stack limit */
	getrlimit (RLIMIT_STACK, &rlim);
	rlim.rlim_cur = 100 * 1024 * 1024;
	rlim.rlim_max = rlim.rlim_cur;
	setrlimit (RLIMIT_STACK, &rlim);

	if (cf->bind_conf) {
		setproctitle ("%s process (%s)", cf->worker->name,
				cf->bind_conf->bind_line);
	}
	else {
		setproctitle ("%s process", cf->worker->name);
	}

	if (rspamd_main->pfh) {
		rspamd_pidfile_close (rspamd_main->pfh);
	}

	if (rspamd_main->cfg->log_silent_workers) {
		rspamd_log_set_log_level (rspamd_main->logger, G_LOG_LEVEL_MESSAGE);
	}

	wrk->start_time = rspamd_get_calendar_ticks ();

	if (cf->bind_conf) {
		GString *listen_conf_stringified = g_string_new (NULL);
		struct rspamd_worker_bind_conf *cur_conf;

		LL_FOREACH (cf->bind_conf, cur_conf) {
			if (cur_conf->next) {
				rspamd_printf_gstring (listen_conf_stringified, "%s, ",
						cur_conf->bind_line);
			}
			else {
				rspamd_printf_gstring (listen_conf_stringified, "%s",
						cur_conf->bind_line);
			}
		}

		msg_info_main ("starting %s process %P (%d); listen on: %v",
				cf->worker->name,
				getpid (), wrk->index, listen_conf_stringified);
		g_string_free (listen_conf_stringified, TRUE);
	}
	else {
		msg_info_main ("starting %s process %P (%d); no listen",
				cf->worker->name,
				getpid (), wrk->index);
	}
	/* Close parent part of socketpair */
	close (wrk->control_pipe[0]);
	close (wrk->srv_pipe[0]);
	rspamd_socket_nonblocking (wrk->control_pipe[1]);
	rspamd_socket_nonblocking (wrk->srv_pipe[1]);
	rspamd_main->cfg->cur_worker = wrk;
	/* Execute worker (this function should not return normally!) */
	cf->worker->worker_start_func (wrk);
	/* To distinguish from normal termination */
	exit (EXIT_FAILURE);
}

static void
rspamd_handle_main_fork (struct rspamd_worker *wrk,
						 struct rspamd_main *rspamd_main,
						 struct rspamd_worker_conf *cf,
						 struct ev_loop *ev_base)
{
	/* Close worker part of socketpair */
	close (wrk->control_pipe[1]);
	close (wrk->srv_pipe[1]);

	rspamd_socket_nonblocking (wrk->control_pipe[0]);
	rspamd_socket_nonblocking (wrk->srv_pipe[0]);
	rspamd_srv_start_watching (rspamd_main, wrk, ev_base);
	/* Child event */
	wrk->cld_ev.data = wrk;
	ev_child_init (&wrk->cld_ev, rspamd_worker_on_term, wrk->pid, 0);
	ev_child_start (rspamd_main->event_loop, &wrk->cld_ev);
	/* Heartbeats */
	rspamd_main_heartbeat_start (wrk, rspamd_main->event_loop);
	/* Insert worker into worker's table, pid is index */
	g_hash_table_insert (rspamd_main->workers,
			GSIZE_TO_POINTER (wrk->pid), wrk);

#if defined(SO_REUSEPORT) && defined(SO_REUSEADDR) && defined(LINUX)
	/*
	 * Close listen sockets in the main process once a child is handling them,
	 * if we have reuseport
	 */
	GList *cur = cf->listen_socks;

	while (cur) {
		struct rspamd_worker_listen_socket *ls =
				(struct rspamd_worker_listen_socket *)cur->data;

		if (ls->fd != -1 && ls->type == RSPAMD_WORKER_SOCKET_UDP) {
			close (ls->fd);
			ls->fd = -1;
		}

		cur = g_list_next (cur);
	}
#endif
}

struct rspamd_worker *
rspamd_fork_worker (struct rspamd_main *rspamd_main,
					struct rspamd_worker_conf *cf,
					guint index,
					struct ev_loop *ev_base,
					rspamd_worker_term_cb term_handler,
					GHashTable *listen_sockets)
{
	struct rspamd_worker *wrk;

	/* Starting worker process */
	wrk = (struct rspamd_worker *) g_malloc0 (sizeof (struct rspamd_worker));

	if (!rspamd_socketpair (wrk->control_pipe, SOCK_DGRAM)) {
		msg_err ("socketpair failure: %s", strerror (errno));
		rspamd_hard_terminate (rspamd_main);
	}

	if (!rspamd_socketpair (wrk->srv_pipe, SOCK_DGRAM)) {
		msg_err ("socketpair failure: %s", strerror (errno));
		rspamd_hard_terminate (rspamd_main);
	}

	if (cf->bind_conf) {
		msg_info_main ("prepare to fork process %s (%d); listen on: %s",
				cf->worker->name,
				index, cf->bind_conf->name);
	}
	else {
		msg_info_main ("prepare to fork process %s (%d), no bind socket",
				cf->worker->name,
				index);
	}

	wrk->srv = rspamd_main;
	wrk->type = cf->type;
	wrk->cf = cf;
	wrk->flags = cf->worker->flags;
	REF_RETAIN (cf);
	wrk->index = index;
	wrk->ctx = cf->ctx;
	wrk->ppid = getpid ();
	wrk->pid = fork ();
	wrk->cores_throttled = rspamd_main->cores_throttling;
	wrk->term_handler = term_handler;
	wrk->control_events_pending = g_hash_table_new_full (g_direct_hash, g_direct_equal,
			NULL, rspamd_pending_control_free);

	switch (wrk->pid) {
	case 0:
		rspamd_handle_child_fork (wrk, rspamd_main, cf, listen_sockets);
		break;
	case -1:
		msg_err_main ("cannot fork main process: %s", strerror (errno));

		if (rspamd_main->pfh) {
			rspamd_pidfile_remove (rspamd_main->pfh);
		}

		rspamd_hard_terminate (rspamd_main);
		break;
	default:
		rspamd_handle_main_fork (wrk, rspamd_main, cf, ev_base);
		break;
	}

	return wrk;
}

void
rspamd_worker_block_signals (void)
{
	sigset_t set;

	sigemptyset (&set);
	sigaddset (&set, SIGTERM);
	sigaddset (&set, SIGINT);
	sigaddset (&set, SIGHUP);
	sigaddset (&set, SIGUSR1);
	sigaddset (&set, SIGUSR2);
	sigprocmask (SIG_BLOCK, &set, NULL);
}

void
rspamd_worker_unblock_signals (void)
{
	sigset_t set;

	sigemptyset (&set);
	sigaddset (&set, SIGTERM);
	sigaddset (&set, SIGINT);
	sigaddset (&set, SIGHUP);
	sigaddset (&set, SIGUSR1);
	sigaddset (&set, SIGUSR2);
	sigprocmask (SIG_UNBLOCK, &set, NULL);
}

void
rspamd_hard_terminate (struct rspamd_main *rspamd_main)
{
	GHashTableIter it;
	gpointer k, v;
	struct rspamd_worker *w;
	sigset_t set;

	/* Block all signals */
	sigemptyset (&set);
	sigaddset (&set, SIGTERM);
	sigaddset (&set, SIGINT);
	sigaddset (&set, SIGHUP);
	sigaddset (&set, SIGUSR1);
	sigaddset (&set, SIGUSR2);
	sigaddset (&set, SIGCHLD);
	sigprocmask (SIG_BLOCK, &set, NULL);

	/* We need to terminate all workers that might be already spawned */
	rspamd_worker_block_signals ();
	g_hash_table_iter_init (&it, rspamd_main->workers);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		w = v;
		msg_err_main ("kill worker %P as Rspamd is terminating due to "
				"an unrecoverable error", w->pid);
		kill (w->pid, SIGKILL);
	}

	msg_err_main ("shutting down Rspamd due to fatal error");

	rspamd_log_close (rspamd_main->logger);
	exit (EXIT_FAILURE);
}

gboolean
rspamd_worker_is_scanner (struct rspamd_worker *w)
{

	if (w) {
		return !!(w->flags & RSPAMD_WORKER_SCANNER);
	}

	return FALSE;
}

gboolean
rspamd_worker_is_primary_controller (struct rspamd_worker *w)
{

	if (w) {
		return !!(w->flags & RSPAMD_WORKER_CONTROLLER) && w->index == 0;
	}

	return FALSE;
}

struct rspamd_worker_session_elt {
	void *ptr;
	guint *pref;
	const gchar *tag;
	time_t when;
};

struct rspamd_worker_session_cache {
	struct ev_loop *ev_base;
	GHashTable *cache;
	struct rspamd_config *cfg;
	struct ev_timer periodic;
};

static gint
rspamd_session_cache_sort_cmp (gconstpointer pa, gconstpointer pb)
{
	const struct rspamd_worker_session_elt
			*e1 = *(const struct rspamd_worker_session_elt **)pa,
			*e2 = *(const struct rspamd_worker_session_elt **)pb;

	return e2->when < e1->when;
}

static void
rspamd_sessions_cache_periodic (EV_P_ ev_timer *w, int revents)
{
	struct rspamd_worker_session_cache *c =
			(struct rspamd_worker_session_cache *)w->data;
	GHashTableIter it;
	gchar timebuf[32];
	gpointer k, v;
	struct rspamd_worker_session_elt *elt;
	struct tm tms;
	GPtrArray *res;
	guint i;

	if (g_hash_table_size (c->cache) > c->cfg->max_sessions_cache) {
		res = g_ptr_array_sized_new (g_hash_table_size (c->cache));
		g_hash_table_iter_init (&it, c->cache);

		while (g_hash_table_iter_next (&it, &k, &v)) {
			g_ptr_array_add (res, v);
		}

		msg_err ("sessions cache is overflowed %d elements where %d is limit",
				(gint)res->len, (gint)c->cfg->max_sessions_cache);
		g_ptr_array_sort (res, rspamd_session_cache_sort_cmp);

		PTR_ARRAY_FOREACH (res, i, elt) {
			rspamd_localtime (elt->when, &tms);
			strftime (timebuf, sizeof (timebuf), "%F %H:%M:%S", &tms);

			msg_warn ("redundant session; ptr: %p, "
					"tag: %s, refcount: %d, time: %s",
					elt->ptr, elt->tag ? elt->tag : "unknown",
					elt->pref ? *elt->pref : 0,
					timebuf);
		}
	}

	ev_timer_again (EV_A_ w);
}

void *
rspamd_worker_session_cache_new (struct rspamd_worker *w,
		struct ev_loop *ev_base)
{
	struct rspamd_worker_session_cache *c;
	static const gdouble periodic_interval = 60.0;

	c = g_malloc0 (sizeof (*c));
	c->ev_base = ev_base;
	c->cache = g_hash_table_new_full (g_direct_hash, g_direct_equal,
			NULL, g_free);
	c->cfg = w->srv->cfg;
	c->periodic.data = c;
	ev_timer_init (&c->periodic, rspamd_sessions_cache_periodic, periodic_interval,
			periodic_interval);
	ev_timer_start (ev_base, &c->periodic);

	return c;
}


void
rspamd_worker_session_cache_add (void *cache, const gchar *tag,
		guint *pref, void *ptr)
{
	struct rspamd_worker_session_cache *c = cache;
	struct rspamd_worker_session_elt *elt;

	elt = g_malloc0 (sizeof (*elt));
	elt->pref = pref;
	elt->ptr = ptr;
	elt->tag = tag;
	elt->when = time (NULL);

	g_hash_table_insert (c->cache, elt->ptr, elt);
}


void
rspamd_worker_session_cache_remove (void *cache, void *ptr)
{
	struct rspamd_worker_session_cache *c = cache;

	g_hash_table_remove (c->cache, ptr);
}

static void
rspamd_worker_monitored_on_change (struct rspamd_monitored_ctx *ctx,
		struct rspamd_monitored *m, gboolean alive,
		void *ud)
{
	struct rspamd_worker *worker = ud;
	struct rspamd_config *cfg = worker->srv->cfg;
	struct ev_loop *ev_base;
	guchar tag[RSPAMD_MONITORED_TAG_LEN];
	static struct rspamd_srv_command srv_cmd;

	rspamd_monitored_get_tag (m, tag);
	ev_base = rspamd_monitored_ctx_get_ev_base (ctx);
	memset (&srv_cmd, 0, sizeof (srv_cmd));
	srv_cmd.type = RSPAMD_SRV_MONITORED_CHANGE;
	rspamd_strlcpy (srv_cmd.cmd.monitored_change.tag, tag,
			sizeof (srv_cmd.cmd.monitored_change.tag));
	srv_cmd.cmd.monitored_change.alive = alive;
	srv_cmd.cmd.monitored_change.sender = getpid ();
	msg_info_config ("broadcast monitored update for %s: %s",
			srv_cmd.cmd.monitored_change.tag, alive ? "alive" : "dead");

	rspamd_srv_send_command (worker, ev_base, &srv_cmd, -1, NULL, NULL);
}

void
rspamd_worker_init_monitored (struct rspamd_worker *worker,
		struct ev_loop *ev_base,
		struct rspamd_dns_resolver *resolver)
{
	rspamd_monitored_ctx_config (worker->srv->cfg->monitored_ctx,
			worker->srv->cfg, ev_base, resolver->r,
			rspamd_worker_monitored_on_change, worker);
}

#ifdef HAVE_SA_SIGINFO

#ifdef WITH_LIBUNWIND
static void
rspamd_print_crash (ucontext_t *uap)
{
	unw_cursor_t cursor;
	unw_word_t ip, off;
	guint level;
	gint ret;

	if ((ret = unw_init_local (&cursor, uap)) != 0) {
		msg_err ("unw_init_local: %d", ret);

		return;
	}

	level = 0;
	ret = 0;

	for (;;) {
		char name[128];

		if (level >= UNWIND_BACKTRACE_DEPTH) {
			break;
		}

		unw_get_reg (&cursor, UNW_REG_IP, &ip);
		ret = unw_get_proc_name(&cursor, name, sizeof (name), &off);

		if (ret == 0) {
			msg_err ("%d: %p: %s()+0x%xl",
				level, ip, name, (uintptr_t)off);
		} else {
			msg_err ("%d: %p: <unknown>", level, ip);
		}

		level++;
		ret = unw_step (&cursor);

		if (ret <= 0) {
			break;
		}
	}

	if (ret < 0) {
		msg_err ("unw_step_ptr: %d", ret);
	}
}
#endif

static struct rspamd_main *saved_main = NULL;
static gboolean
rspamd_crash_propagate (gpointer key, gpointer value, gpointer unused)
{
	struct rspamd_worker *w = value;

	/* Kill children softly */
	kill (w->pid, SIGTERM);

	return TRUE;
}

static void
rspamd_crash_sig_handler (int sig, siginfo_t *info, void *ctx)
{
	struct sigaction sa;
	ucontext_t *uap = ctx;
	pid_t pid;

	pid = getpid ();
	msg_err ("caught fatal signal %d(%s), "
			 "pid: %P, trace: ",
			sig, strsignal (sig), pid);
	(void)uap;
#ifdef WITH_LIBUNWIND
	rspamd_print_crash (uap);
#endif
	msg_err ("please see Rspamd FAQ to learn how to dump core files and how to "
			 "fill a bug report");

	if (saved_main) {
		if (pid == saved_main->pid) {
			/*
			 * Main process has crashed, propagate crash further to trigger
			 * monitoring alerts and mass panic
			 */
			g_hash_table_foreach_remove (saved_main->workers,
					rspamd_crash_propagate, NULL);
		}
	}

	/*
	 * Invoke signal with the default handler
	 */
	sigemptyset (&sa.sa_mask);
	sa.sa_handler = SIG_DFL;
	sa.sa_flags = 0;
	sigaction (sig, &sa, NULL);
	kill (pid, sig);
}
#endif

RSPAMD_NO_SANITIZE void
rspamd_set_crash_handler (struct rspamd_main *rspamd_main)
{
#ifdef HAVE_SA_SIGINFO
	struct sigaction sa;

#ifdef HAVE_SIGALTSTACK
	void *stack_mem;
	stack_t ss;
	memset (&ss, 0, sizeof ss);

	/*
	 * Allocate special stack, NOT freed at the end so far
	 * It also cannot be on stack as this memory is used when
	 * stack corruption is detected. Leak sanitizer blames about it but
	 * I don't know any good ways to stop this behaviour.
	 */
	ss.ss_size = MAX (SIGSTKSZ, 8192 * 4);
	stack_mem = g_malloc0 (ss.ss_size);
	ss.ss_sp = stack_mem;
	sigaltstack (&ss, NULL);
#endif
	saved_main = rspamd_main;
	sigemptyset (&sa.sa_mask);
	sa.sa_sigaction = &rspamd_crash_sig_handler;
	sa.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;
	sigaction (SIGSEGV, &sa, NULL);
	sigaction (SIGBUS, &sa, NULL);
	sigaction (SIGABRT, &sa, NULL);
	sigaction (SIGFPE, &sa, NULL);
	sigaction (SIGSYS, &sa, NULL);
#endif
}

static void
rspamd_enable_accept_event (EV_P_ ev_timer *w, int revents)
{
	struct rspamd_worker_accept_event *ac_ev =
			(struct rspamd_worker_accept_event *)w->data;

	ev_timer_stop (EV_A_ w);
	ev_io_start (EV_A_ &ac_ev->accept_ev);
}

void
rspamd_worker_throttle_accept_events (gint sock, void *data)
{
	struct rspamd_worker_accept_event *head, *cur;
	const gdouble throttling = 0.5;

	head = (struct rspamd_worker_accept_event *)data;

	DL_FOREACH (head, cur) {

		ev_io_stop (cur->event_loop, &cur->accept_ev);
		cur->throttling_ev.data = cur;
		ev_timer_init (&cur->throttling_ev, rspamd_enable_accept_event,
				throttling, 0.0);
		ev_timer_start (cur->event_loop, &cur->throttling_ev);
	}
}

gboolean
rspamd_check_termination_clause (struct rspamd_main *rspamd_main,
								 struct rspamd_worker *wrk,
								 int res)
{
	gboolean need_refork = TRUE;

	if (wrk->state != rspamd_worker_state_running || rspamd_main->wanna_die ||
			(wrk->flags & RSPAMD_WORKER_OLD_CONFIG)) {
		/* Do not refork workers that are intended to be terminated */
		need_refork = FALSE;
	}

	if (WIFEXITED (res) && WEXITSTATUS (res) == 0) {
		/* Normal worker termination, do not fork one more */

		if (wrk->flags & RSPAMD_WORKER_OLD_CONFIG) {
			/* Never re-fork old workers */
			msg_info_main ("%s process %P terminated normally",
					g_quark_to_string(wrk->type),
					wrk->pid);
			need_refork = FALSE;
		}
		else {
			if (wrk->hb.nbeats < 0 && rspamd_main->cfg->heartbeats_loss_max > 0 &&
				-(wrk->hb.nbeats) >= rspamd_main->cfg->heartbeats_loss_max) {
				msg_info_main ("%s process %P terminated normally, but lost %L "
							   "heartbeats, refork it",
						g_quark_to_string(wrk->type),
						wrk->pid,
						-(wrk->hb.nbeats));
				need_refork = TRUE;
			}
			else {
				msg_info_main ("%s process %P terminated normally",
						g_quark_to_string(wrk->type),
						wrk->pid);
				need_refork = FALSE;
			}
		}
	}
	else {
		if (WIFSIGNALED (res)) {
#ifdef WCOREDUMP
			if (WCOREDUMP (res)) {
				msg_warn_main (
						"%s process %P terminated abnormally by signal: %s"
						" and created core file; please see Rspamd FAQ "
						"to learn how to extract data from core file and "
						"fill a bug report",
						g_quark_to_string (wrk->type),
						wrk->pid,
						g_strsignal (WTERMSIG (res)));
			}
			else {
#ifdef HAVE_SYS_RESOURCE_H
				struct rlimit rlmt;
				(void) getrlimit (RLIMIT_CORE, &rlmt);

				msg_warn_main (
						"%s process %P terminated abnormally with exit code %d by "
						"signal: %s"
						" but NOT created core file (throttled=%s); "
						"core file limits: %L current, %L max",
						g_quark_to_string (wrk->type),
						wrk->pid,
						WEXITSTATUS (res),
						g_strsignal (WTERMSIG (res)),
						wrk->cores_throttled ? "yes" : "no",
						(gint64) rlmt.rlim_cur,
						(gint64) rlmt.rlim_max);
#else
				msg_warn_main (
								"%s process %P terminated abnormally with exit code %d by signal: %s"
								" but NOT created core file (throttled=%s); ",
								g_quark_to_string (wrk->type),
								wrk->pid, WEXITSTATUS (res),
								g_strsignal (WTERMSIG (res)),
								wrk->cores_throttled ? "yes" : "no");
#endif
			}
#else
			msg_warn_main (
							"%s process %P terminated abnormally with exit code %d by signal: %s",
							g_quark_to_string (wrk->type),
							wrk->pid, WEXITSTATUS (res),
							g_strsignal (WTERMSIG (res)));
#endif
			if (WTERMSIG (res) == SIGUSR2) {
				/*
				 * It is actually race condition when not started process
				 * has been requested to be reloaded.
				 *
				 * We shouldn't refork on this
				 */
				need_refork = FALSE;
			}
		}
		else {
			msg_warn_main ("%s process %P terminated abnormally "
						   "(but it was not killed by a signal) "
						   "with exit code %d",
					g_quark_to_string (wrk->type),
					wrk->pid,
					WEXITSTATUS (res));
		}
	}

	return need_refork;
}

#ifdef WITH_HYPERSCAN
gboolean
rspamd_worker_hyperscan_ready (struct rspamd_main *rspamd_main,
							   struct rspamd_worker *worker, gint fd,
							   gint attached_fd,
							   struct rspamd_control_command *cmd,
							   gpointer ud) {
	struct rspamd_control_reply rep;
	struct rspamd_re_cache *cache = worker->srv->cfg->re_cache;

	memset (&rep, 0, sizeof (rep));
	rep.type = RSPAMD_CONTROL_HYPERSCAN_LOADED;

	if (rspamd_re_cache_is_hs_loaded (cache) != RSPAMD_HYPERSCAN_LOADED_FULL ||
		cmd->cmd.hs_loaded.forced) {

		msg_info ("loading hyperscan expressions after receiving compilation "
				  "notice: %s",
				(rspamd_re_cache_is_hs_loaded (cache) != RSPAMD_HYPERSCAN_LOADED_FULL) ?
				"new db" : "forced update");
		rep.reply.hs_loaded.status = rspamd_re_cache_load_hyperscan (
				worker->srv->cfg->re_cache, cmd->cmd.hs_loaded.cache_dir, false);
	}

	if (write (fd, &rep, sizeof (rep)) != sizeof (rep)) {
		msg_err ("cannot write reply to the control socket: %s",
				strerror (errno));
	}

	return TRUE;
}
#endif /* With Hyperscan */

gboolean
rspamd_worker_check_context (gpointer ctx, guint64 magic)
{
	struct rspamd_abstract_worker_ctx *actx = (struct rspamd_abstract_worker_ctx*)ctx;

	return actx->magic == magic;
}

static gboolean
rspamd_worker_log_pipe_handler (struct rspamd_main *rspamd_main,
								struct rspamd_worker *worker, gint fd,
								gint attached_fd,
								struct rspamd_control_command *cmd,
								gpointer ud)
{
	struct rspamd_config *cfg = ud;
	struct rspamd_worker_log_pipe *lp;
	struct rspamd_control_reply rep;

	memset (&rep, 0, sizeof (rep));
	rep.type = RSPAMD_CONTROL_LOG_PIPE;

	if (attached_fd != -1) {
		lp = g_malloc0 (sizeof (*lp));
		lp->fd = attached_fd;
		lp->type = cmd->cmd.log_pipe.type;

		DL_APPEND (cfg->log_pipes, lp);
		msg_info ("added new log pipe");
	}
	else {
		rep.reply.log_pipe.status = ENOENT;
		msg_err ("cannot attach log pipe: invalid fd");
	}

	if (write (fd, &rep, sizeof (rep)) != sizeof (rep)) {
		msg_err ("cannot write reply to the control socket: %s",
				strerror (errno));
	}

	return TRUE;
}

static gboolean
rspamd_worker_monitored_handler (struct rspamd_main *rspamd_main,
								 struct rspamd_worker *worker, gint fd,
								 gint attached_fd,
								 struct rspamd_control_command *cmd,
								 gpointer ud)
{
	struct rspamd_control_reply rep;
	struct rspamd_monitored *m;
	struct rspamd_monitored_ctx *mctx = worker->srv->cfg->monitored_ctx;
	struct rspamd_config *cfg = ud;

	memset (&rep, 0, sizeof (rep));
	rep.type = RSPAMD_CONTROL_MONITORED_CHANGE;

	if (cmd->cmd.monitored_change.sender != getpid ()) {
		m = rspamd_monitored_by_tag (mctx, cmd->cmd.monitored_change.tag);

		if (m != NULL) {
			rspamd_monitored_set_alive (m, cmd->cmd.monitored_change.alive);
			rep.reply.monitored_change.status = 1;
			msg_info_config ("updated monitored status for %s: %s",
					cmd->cmd.monitored_change.tag,
					cmd->cmd.monitored_change.alive ? "alive" : "dead");
		} else {
			msg_err ("cannot find monitored by tag: %*s", 32,
					cmd->cmd.monitored_change.tag);
			rep.reply.monitored_change.status = 0;
		}
	}

	if (write (fd, &rep, sizeof (rep)) != sizeof (rep)) {
		msg_err ("cannot write reply to the control socket: %s",
				strerror (errno));
	}

	return TRUE;
}

void
rspamd_worker_init_scanner (struct rspamd_worker *worker,
							struct ev_loop *ev_base,
							struct rspamd_dns_resolver *resolver,
							struct rspamd_lang_detector **plang_det)
{
	rspamd_stat_init (worker->srv->cfg, ev_base);
#ifdef WITH_HYPERSCAN
	rspamd_control_worker_add_cmd_handler (worker,
			RSPAMD_CONTROL_HYPERSCAN_LOADED,
			rspamd_worker_hyperscan_ready,
			NULL);
#endif
	rspamd_control_worker_add_cmd_handler (worker,
			RSPAMD_CONTROL_LOG_PIPE,
			rspamd_worker_log_pipe_handler,
			worker->srv->cfg);
	rspamd_control_worker_add_cmd_handler (worker,
			RSPAMD_CONTROL_MONITORED_CHANGE,
			rspamd_worker_monitored_handler,
			worker->srv->cfg);

	*plang_det = worker->srv->cfg->lang_det;
}

void
rspamd_controller_store_saved_stats (struct rspamd_main *rspamd_main,
									 struct rspamd_config *cfg)
{
	struct rspamd_stat *stat;
	ucl_object_t *top, *sub;
	struct ucl_emitter_functions *efuncs;
	gint i, fd;
	FILE *fp;
	gchar fpath[PATH_MAX];

	if (cfg->stats_file == NULL) {
		return;
	}

	rspamd_snprintf (fpath, sizeof (fpath), "%s.XXXXXXXX", cfg->stats_file);
	fd = g_mkstemp_full (fpath, O_WRONLY|O_TRUNC, 00644);

	if (fd == -1) {
		msg_err_config ("cannot open for writing controller stats from %s: %s",
				fpath, strerror (errno));
		return;
	}

	fp = fdopen (fd, "w");
	stat = rspamd_main->stat;

	top = ucl_object_typed_new (UCL_OBJECT);
	ucl_object_insert_key (top, ucl_object_fromint (
			stat->messages_scanned), "scanned", 0, false);
	ucl_object_insert_key (top, ucl_object_fromint (
			stat->messages_learned), "learned", 0, false);

	if (stat->messages_scanned > 0) {
		sub = ucl_object_typed_new (UCL_OBJECT);
		for (i = METRIC_ACTION_REJECT; i <= METRIC_ACTION_NOACTION; i++) {
			ucl_object_insert_key (sub,
					ucl_object_fromint (stat->actions_stat[i]),
					rspamd_action_to_str (i), 0, false);
		}
		ucl_object_insert_key (top, sub, "actions", 0, false);
	}

	ucl_object_insert_key (top,
			ucl_object_fromint (stat->connections_count),
			"connections", 0, false);
	ucl_object_insert_key (top,
			ucl_object_fromint (stat->control_connections_count),
			"control_connections", 0, false);

	efuncs = ucl_object_emit_file_funcs (fp);
	if (!ucl_object_emit_full (top, UCL_EMIT_JSON_COMPACT,
			efuncs, NULL)) {
		msg_err_config ("cannot write stats to %s: %s",
				fpath, strerror (errno));

		unlink (fpath);
	}
	else {
		if (rename (fpath, cfg->stats_file) == -1) {
			msg_err_config ("cannot rename stats from %s to %s: %s",
					fpath, cfg->stats_file, strerror (errno));
		}
	}

	ucl_object_unref (top);
	fclose (fp);
	ucl_object_emit_funcs_free (efuncs);
}

static ev_timer rrd_timer;

void
rspamd_controller_on_terminate (struct rspamd_worker *worker,
								struct rspamd_rrd_file *rrd)
{
	struct rspamd_abstract_worker_ctx *ctx;

	ctx = (struct rspamd_abstract_worker_ctx *)worker->ctx;
	rspamd_controller_store_saved_stats (worker->srv, worker->srv->cfg);

	if (rrd) {
		ev_timer_stop (ctx->event_loop, &rrd_timer);
		msg_info ("closing rrd file: %s", rrd->filename);
		rspamd_rrd_close (rrd);
	}
}

static void
rspamd_controller_load_saved_stats (struct rspamd_main *rspamd_main,
									struct rspamd_config *cfg)
{
	struct ucl_parser *parser;
	ucl_object_t *obj;
	const ucl_object_t *elt, *subelt;
	struct rspamd_stat *stat, stat_copy;
	gint i;

	if (cfg->stats_file == NULL) {
		return;
	}

	if (access (cfg->stats_file, R_OK) == -1) {
		msg_err_config ("cannot load controller stats from %s: %s",
				cfg->stats_file, strerror (errno));
		return;
	}

	parser = ucl_parser_new (0);

	if (!ucl_parser_add_file (parser, cfg->stats_file)) {
		msg_err_config ("cannot parse controller stats from %s: %s",
				cfg->stats_file, ucl_parser_get_error (parser));
		ucl_parser_free (parser);

		return;
	}

	obj = ucl_parser_get_object (parser);
	ucl_parser_free (parser);

	stat = rspamd_main->stat;
	memcpy (&stat_copy, stat, sizeof (stat_copy));

	elt = ucl_object_lookup (obj, "scanned");

	if (elt != NULL && ucl_object_type (elt) == UCL_INT) {
		stat_copy.messages_scanned = ucl_object_toint (elt);
	}

	elt = ucl_object_lookup (obj, "learned");

	if (elt != NULL && ucl_object_type (elt) == UCL_INT) {
		stat_copy.messages_learned = ucl_object_toint (elt);
	}

	elt = ucl_object_lookup (obj, "actions");

	if (elt != NULL) {
		for (i = METRIC_ACTION_REJECT; i <= METRIC_ACTION_NOACTION; i++) {
			subelt = ucl_object_lookup (elt, rspamd_action_to_str (i));

			if (subelt && ucl_object_type (subelt) == UCL_INT) {
				stat_copy.actions_stat[i] = ucl_object_toint (subelt);
			}
		}
	}

	elt = ucl_object_lookup (obj, "connections_count");

	if (elt != NULL && ucl_object_type (elt) == UCL_INT) {
		stat_copy.connections_count = ucl_object_toint (elt);
	}

	elt = ucl_object_lookup (obj, "control_connections_count");

	if (elt != NULL && ucl_object_type (elt) == UCL_INT) {
		stat_copy.control_connections_count = ucl_object_toint (elt);
	}

	ucl_object_unref (obj);
	memcpy (stat, &stat_copy, sizeof (stat_copy));
}

struct rspamd_controller_periodics_cbdata {
	struct rspamd_worker *worker;
	struct rspamd_rrd_file *rrd;
	struct rspamd_stat *stat;
	ev_timer save_stats_event;
};

static void
rspamd_controller_rrd_update (EV_P_ ev_timer *w, int revents)
{
	struct rspamd_controller_periodics_cbdata *cbd =
			(struct rspamd_controller_periodics_cbdata *)w->data;
	struct rspamd_stat *stat;
	GArray ar;
	gdouble points[METRIC_ACTION_MAX];
	GError *err = NULL;
	guint i;

	g_assert (cbd->rrd != NULL);
	stat = cbd->stat;

	for (i = METRIC_ACTION_REJECT; i < METRIC_ACTION_MAX; i ++) {
		points[i] = stat->actions_stat[i];
	}

	ar.data = (gchar *)points;
	ar.len = sizeof (points);

	if (!rspamd_rrd_add_record (cbd->rrd, &ar, rspamd_get_calendar_ticks (),
			&err)) {
		msg_err ("cannot update rrd file: %e", err);
		g_error_free (err);
	}

	/* Plan new event */
	ev_timer_again (EV_A_ w);
}

static void
rspamd_controller_stats_save_periodic (EV_P_ ev_timer *w, int revents)
{
	struct rspamd_controller_periodics_cbdata *cbd =
			(struct rspamd_controller_periodics_cbdata *)w->data;

	rspamd_controller_store_saved_stats (cbd->worker->srv, cbd->worker->srv->cfg);
	ev_timer_again (EV_A_ w);
}

void
rspamd_worker_init_controller (struct rspamd_worker *worker,
							   struct rspamd_rrd_file **prrd)
{
	struct rspamd_abstract_worker_ctx *ctx;
	static const ev_tstamp rrd_update_time = 1.0;

	ctx = (struct rspamd_abstract_worker_ctx *)worker->ctx;
	rspamd_controller_load_saved_stats (worker->srv, worker->srv->cfg);

	if (worker->index == 0) {
		/* Enable periodics and other stuff */
		static struct rspamd_controller_periodics_cbdata cbd;
		const ev_tstamp save_stats_interval = 60; /* 1 minute */

		memset (&cbd, 0, sizeof (cbd));
		cbd.save_stats_event.data = &cbd;
		cbd.worker = worker;
		cbd.stat = worker->srv->stat;

		ev_timer_init (&cbd.save_stats_event,
				rspamd_controller_stats_save_periodic,
				save_stats_interval, save_stats_interval);
		ev_timer_start (ctx->event_loop, &cbd.save_stats_event);

		rspamd_map_watch (worker->srv->cfg, ctx->event_loop,
				ctx->resolver, worker,
				RSPAMD_MAP_WATCH_PRIMARY_CONTROLLER);

		if (prrd != NULL) {
			if (ctx->cfg->rrd_file && worker->index == 0) {
				GError *rrd_err = NULL;

				*prrd = rspamd_rrd_file_default (ctx->cfg->rrd_file, &rrd_err);

				if (*prrd) {
					cbd.rrd = *prrd;
					rrd_timer.data = &cbd;
					ev_timer_init (&rrd_timer, rspamd_controller_rrd_update,
							rrd_update_time, rrd_update_time);
					ev_timer_start (ctx->event_loop, &rrd_timer);
				}
				else if (rrd_err) {
					msg_err ("cannot load rrd from %s: %e", ctx->cfg->rrd_file,
							rrd_err);
					g_error_free (rrd_err);
				}
				else {
					msg_err ("cannot load rrd from %s: unknown error",
							ctx->cfg->rrd_file);
				}
			}
			else {
				*prrd = NULL;
			}
		}

		if (!ctx->cfg->disable_monitored) {
			rspamd_worker_init_monitored (worker,
					ctx->event_loop, ctx->resolver);
		}
	}
	else {
		rspamd_map_watch (worker->srv->cfg, ctx->event_loop,
				ctx->resolver, worker, RSPAMD_MAP_WATCH_SCANNER);
	}
}
