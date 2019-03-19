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
#include "libutil/map.h"
#include "libutil/map_private.h"
#include "libutil/http_private.h"
#include "libutil/http_router.h"

#ifdef WITH_GPERF_TOOLS
#include <gperftools/profiler.h>
#endif
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

static void rspamd_worker_ignore_signal (int signo);
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

static gboolean
rspamd_worker_terminate_handlers (struct rspamd_worker *w)
{
	guint i;
	gboolean (*cb)(struct rspamd_worker *);
	gboolean ret = FALSE;

	for (i = 0; i < w->finish_actions->len; i ++) {
		cb = g_ptr_array_index (w->finish_actions, i);
		if (cb (w)) {
			ret = TRUE;
		}
	}

	return ret;
}
/*
 * Config reload is designed by sending sigusr2 to active workers and pending shutdown of them
 */
static gboolean
rspamd_worker_usr2_handler (struct rspamd_worker_signal_handler *sigh, void *arg)
{
	/* Do not accept new connections, preparing to end worker's process */
	struct timeval tv;

	if (!sigh->worker->wanna_die) {
		rspamd_worker_ignore_signal (SIGUSR2);
		tv.tv_sec = SOFT_SHUTDOWN_TIME;
		tv.tv_usec = 0;
		sigh->worker->wanna_die = TRUE;
		rspamd_worker_terminate_handlers (sigh->worker);
		rspamd_default_log_function (G_LOG_LEVEL_INFO,
				sigh->worker->srv->server_pool->tag.tagname,
				sigh->worker->srv->server_pool->tag.uid,
				G_STRFUNC,
				"worker's shutdown is pending in %d sec",
				SOFT_SHUTDOWN_TIME);
		event_base_loopexit (sigh->base, &tv);
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
	rspamd_log_reopen (sigh->worker->srv->logger);

	/* Get more signals */
	return TRUE;
}

static gboolean
rspamd_worker_term_handler (struct rspamd_worker_signal_handler *sigh, void *arg)
{
	struct timeval tv;

	if (!sigh->worker->wanna_die) {
		rspamd_default_log_function (G_LOG_LEVEL_INFO,
				sigh->worker->srv->server_pool->tag.tagname,
				sigh->worker->srv->server_pool->tag.uid,
				G_STRFUNC,
				"terminating after receiving signal %s",
				g_strsignal (sigh->signo));

		tv.tv_usec = 0;
		if (rspamd_worker_terminate_handlers (sigh->worker)) {
			tv.tv_sec =  SOFT_SHUTDOWN_TIME;
		}
		else {
			tv.tv_sec = 0;
		}

		sigh->worker->wanna_die = 1;
		event_base_loopexit (sigh->base, &tv);
#ifdef WITH_GPERF_TOOLS
		ProfilerStop ();
#endif
		rspamd_worker_stop_accept (sigh->worker);
	}

	/* Stop reacting on signals */
	return FALSE;
}

static void
rspamd_worker_signal_handle (int fd, short what, void *arg)
{
	struct rspamd_worker_signal_handler *sigh =
			(struct rspamd_worker_signal_handler *) arg;
	struct rspamd_worker_signal_cb *cb, *cbtmp;

	/* Call all signal handlers registered */
	DL_FOREACH_SAFE (sigh->cb, cb, cbtmp) {
		if (!cb->handler (sigh, cb->handler_data)) {
			DL_DELETE (sigh->cb, cb);
		}
	}
}

static void
rspamd_worker_ignore_signal (int signo)
{
	struct sigaction sig;

	sigemptyset (&sig.sa_mask);
	sigaddset (&sig.sa_mask, signo);
	sig.sa_handler = SIG_IGN;
	sig.sa_flags = 0;
	sigaction (signo, &sig, NULL);
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
	struct rspamd_worker_signal_cb *cb, *tmp;

	DL_FOREACH_SAFE (sigh->cb, cb, tmp) {
		DL_DELETE (sigh->cb, cb);
		g_free (cb);
	}

	event_del (&sigh->ev);
	rspamd_worker_default_signal (sigh->signo);
	g_free (sigh);
}

void
rspamd_worker_set_signal_handler (int signo, struct rspamd_worker *worker,
		struct event_base *base,
		rspamd_worker_signal_handler handler,
		void *handler_data)
{
	struct rspamd_worker_signal_handler *sigh;
	struct rspamd_worker_signal_cb *cb;

	sigh = g_hash_table_lookup (worker->signal_events, GINT_TO_POINTER (signo));

	if (sigh == NULL) {
		sigh = g_malloc0 (sizeof (*sigh));
		sigh->signo = signo;
		sigh->worker = worker;
		sigh->base = base;
		sigh->enabled = TRUE;

		signal_set (&sigh->ev, signo, rspamd_worker_signal_handle, sigh);
		event_base_set (base, &sigh->ev);
		signal_add (&sigh->ev, NULL);

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
rspamd_worker_init_signals (struct rspamd_worker *worker, struct event_base *base)
{
	struct sigaction signals;
	/* We ignore these signals in the worker */
	rspamd_worker_ignore_signal (SIGPIPE);
	rspamd_worker_ignore_signal (SIGALRM);
	rspamd_worker_ignore_signal (SIGCHLD);

	/* A set of terminating signals */
	rspamd_worker_set_signal_handler (SIGTERM, worker, base,
			rspamd_worker_term_handler, NULL);
	rspamd_worker_set_signal_handler (SIGINT, worker, base,
			rspamd_worker_term_handler, NULL);
	rspamd_worker_set_signal_handler (SIGHUP, worker, base,
			rspamd_worker_term_handler, NULL);

	/* Special purpose signals */
	rspamd_worker_set_signal_handler (SIGUSR1, worker, base,
			rspamd_worker_usr1_handler, NULL);
	rspamd_worker_set_signal_handler (SIGUSR2, worker, base,
			rspamd_worker_usr2_handler, NULL);

	/* Unblock all signals processed */
	sigemptyset (&signals.sa_mask);
	sigaddset (&signals.sa_mask, SIGTERM);
	sigaddset (&signals.sa_mask, SIGINT);
	sigaddset (&signals.sa_mask, SIGHUP);
	sigaddset (&signals.sa_mask, SIGCHLD);
	sigaddset (&signals.sa_mask, SIGUSR1);
	sigaddset (&signals.sa_mask, SIGUSR2);
	sigaddset (&signals.sa_mask, SIGALRM);
	sigaddset (&signals.sa_mask, SIGPIPE);

	sigprocmask (SIG_UNBLOCK, &signals.sa_mask, NULL);
}

struct event_base *
rspamd_prepare_worker (struct rspamd_worker *worker, const char *name,
	void (*accept_handler)(int, short, void *))
{
	struct event_base *ev_base;
	struct event *accept_events;
	GList *cur;
	struct rspamd_worker_listen_socket *ls;

#ifdef WITH_PROFILER
	extern void _start (void), etext (void);
	monstartup ((u_long) & _start, (u_long) & etext);
#endif

	gperf_profiler_init (worker->srv->cfg, name);

	worker->signal_events = g_hash_table_new_full (g_direct_hash, g_direct_equal,
			NULL, rspamd_sigh_free);

	ev_base = event_init ();

	rspamd_worker_init_signals (worker, ev_base);
	rspamd_control_worker_add_default_handler (worker, ev_base);
#ifdef WITH_HIREDIS
	rspamd_redis_pool_config (worker->srv->cfg->redis_pool,
			worker->srv->cfg, ev_base);
#endif

	/* Accept all sockets */
	if (accept_handler) {
		cur = worker->cf->listen_socks;

		while (cur) {
			ls = cur->data;

			if (ls->fd != -1) {
				accept_events = g_malloc0 (sizeof (struct event) * 2);
				event_set (&accept_events[0], ls->fd, EV_READ | EV_PERSIST,
						accept_handler, worker);
				event_base_set (ev_base, &accept_events[0]);
				event_add (&accept_events[0], NULL);
				worker->accept_events = g_list_prepend (worker->accept_events,
						accept_events);
			}

			cur = g_list_next (cur);
		}
	}

	return ev_base;
}

void
rspamd_worker_stop_accept (struct rspamd_worker *worker)
{
	GList *cur;
	struct event *events;

	/* Remove all events */
	cur = worker->accept_events;
	while (cur) {
		events = cur->data;

		if (rspamd_event_pending (&events[0], EV_TIMEOUT|EV_READ|EV_WRITE)) {
			event_del (&events[0]);
		}

		if (rspamd_event_pending (&events[1], EV_TIMEOUT|EV_READ|EV_WRITE)) {
			event_del (&events[1]);
		}

		cur = g_list_next (cur);
		g_free (events);
	}

	if (worker->accept_events != NULL) {
		g_list_free (worker->accept_events);
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
		entry->rt->ptv);
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
		entry->rt->ptv);
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
		entry->rt->ptv);
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

struct rspamd_worker *
rspamd_fork_worker (struct rspamd_main *rspamd_main,
		struct rspamd_worker_conf *cf,
		guint index,
		struct event_base *ev_base)
{
	struct rspamd_worker *wrk;
	gint rc;
	struct rlimit rlim;

	/* Starting worker process */
	wrk = (struct rspamd_worker *) g_malloc0 (sizeof (struct rspamd_worker));

	if (!rspamd_socketpair (wrk->control_pipe, 0)) {
		msg_err ("socketpair failure: %s", strerror (errno));
		rspamd_hard_terminate (rspamd_main);
	}

	if (!rspamd_socketpair (wrk->srv_pipe, 0)) {
		msg_err ("socketpair failure: %s", strerror (errno));
		rspamd_hard_terminate (rspamd_main);
	}

	wrk->srv = rspamd_main;
	wrk->type = cf->type;
	wrk->cf = cf;
	wrk->flags = cf->worker->flags;
	REF_RETAIN (cf);
	wrk->index = index;
	wrk->ctx = cf->ctx;
	wrk->finish_actions = g_ptr_array_new ();
	wrk->ppid = getpid ();
	wrk->pid = fork ();
	wrk->cores_throttled = rspamd_main->cores_throttling;

	switch (wrk->pid) {
	case 0:
		/* Update pid for logging */
		rspamd_log_update_pid (cf->type, rspamd_main->logger);
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

		/* Remove the inherited event base */
		event_reinit (rspamd_main->ev_base);
		event_base_free (rspamd_main->ev_base);

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

		/* Do silent log reopen to avoid collisions */
		rspamd_log_close (rspamd_main->logger, FALSE);


		if (rspamd_main->cfg->log_silent_workers) {
			rspamd_main->cfg->log_level = G_LOG_LEVEL_MESSAGE;
			rspamd_set_logger (rspamd_main->cfg, cf->type,
					&rspamd_main->logger, rspamd_main->server_pool);
		}

		rspamd_log_open (rspamd_main->logger);
		wrk->start_time = rspamd_get_calendar_ticks ();

#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
		# if (GLIB_MINOR_VERSION > 20)
		/* Ugly hack for old glib */
		if (!g_thread_get_initialized ()) {
			g_thread_init (NULL);
		}
# else
		g_thread_init (NULL);
# endif
#endif
		if (cf->bind_conf) {
			msg_info_main ("starting %s process %P (%d); listen on: %s",
					cf->worker->name,
					getpid (), index, cf->bind_conf->bind_line);
		}
		else {
			msg_info_main ("starting %s process %P (%d)", cf->worker->name,
					getpid (), index);
		}
		/* Close parent part of socketpair */
		close (wrk->control_pipe[0]);
		close (wrk->srv_pipe[0]);
		rspamd_socket_nonblocking (wrk->control_pipe[1]);
		rspamd_socket_nonblocking (wrk->srv_pipe[1]);
		/* Execute worker */
		cf->worker->worker_start_func (wrk);
		exit (EXIT_FAILURE);
		break;
	case -1:
		msg_err_main ("cannot fork main process. %s", strerror (errno));

		if (rspamd_main->pfh) {
			rspamd_pidfile_remove (rspamd_main->pfh);
		}

		rspamd_hard_terminate (rspamd_main);
		break;
	default:
		/* Close worker part of socketpair */
		close (wrk->control_pipe[1]);
		close (wrk->srv_pipe[1]);
		rspamd_socket_nonblocking (wrk->control_pipe[0]);
		rspamd_socket_nonblocking (wrk->srv_pipe[0]);
		rspamd_srv_start_watching (rspamd_main, wrk, ev_base);
		/* Insert worker into worker's table, pid is index */
		g_hash_table_insert (rspamd_main->workers, GSIZE_TO_POINTER (
				wrk->pid), wrk);
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

	rspamd_log_close (rspamd_main->logger, TRUE);
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
	struct event_base *ev_base;
	GHashTable *cache;
	struct rspamd_config *cfg;
	struct timeval tv;
	struct event periodic;
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
rspamd_sessions_cache_periodic (gint fd, short what, gpointer p)
{
	struct rspamd_worker_session_cache *c = p;
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
}

void *
rspamd_worker_session_cache_new (struct rspamd_worker *w,
		struct event_base *ev_base)
{
	struct rspamd_worker_session_cache *c;
	static const gdouble periodic_interval = 60.0;

	c = g_malloc0 (sizeof (*c));
	c->ev_base = ev_base;
	c->cache = g_hash_table_new_full (g_direct_hash, g_direct_equal,
			NULL, g_free);
	c->cfg = w->srv->cfg;
	double_to_tv (periodic_interval, &c->tv);
	event_set (&c->periodic, -1, EV_TIMEOUT|EV_PERSIST,
			rspamd_sessions_cache_periodic, c);
	event_base_set (ev_base, &c->periodic);
	event_add (&c->periodic, &c->tv);

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
	struct event_base *ev_base;
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
		struct event_base *ev_base,
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

void
rspamd_set_crash_handler (struct rspamd_main *rspamd_main)
{
#ifdef HAVE_SA_SIGINFO
	struct sigaction sa;

#ifdef HAVE_SIGALTSTACK
	stack_t ss;
	memset (&ss, 0, sizeof ss);

	/* Allocate special stack, NOT freed at the end so far */
	ss.ss_size = MAX (SIGSTKSZ, 8192 * 4);
	ss.ss_sp = g_malloc0 (ss.ss_size);
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